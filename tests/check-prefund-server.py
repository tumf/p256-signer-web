"""Real local HTTP checks of the prefund page against serve.py and a fake read-only upstream on loopback.

Exercises the actual handler over the built dist/: prefund.html served with the unchanged constrained deployment CSP
(no Verify frame), its entry in the asset manifest, plain relative navigation in both directions, every read the prefund
reader/settlement issues forwarded unchanged, and every send/sign/estimate/funding-call shape rejected before forwarding.
The relay allowlist and reader selectors are byte-identical (no generic RPC expansion). The pinned GPL EntryPoint
runtime never appears in any served asset. Prints one JSON summary line.
"""
import importlib.util
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location("check_server", HERE / "check-server.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
relay_spec = importlib.util.spec_from_file_location("relay", HERE.parent / "serve.py")
relay = importlib.util.module_from_spec(relay_spec)
relay_spec.loader.exec_module(relay)

ACCOUNT = base.ACCOUNT
ENTRYPOINT = base.ENTRYPOINT
DEPLOYMENT_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
                  "connect-src 'self' wss://relay.walletconnect.com https://relay.walletconnect.com; "
                  "base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'")
BALANCE_OF = "0x70a08231" + "00" * 12 + ACCOUNT[2:]
DEPOSIT_TO = "0xb760faf9" + "00" * 12 + ACCOUNT[2:]
check = base.check
rpc = base.rpc


def main():
    runtime = json.loads((ROOT / "tests/fixtures/EntryPoint/entrypoint-runtime.json").read_text())["runtime"][2:]
    dist = HERE.parent / "dist"
    manifest = json.loads((dist / "asset-manifest.json").read_text())
    check("manifest-prefund", "prefund.html" in manifest["files"] and "prefund.js" in manifest["files"])
    leaked = [name for name in manifest["files"]
              if runtime[200:400].encode() in (dist / name).read_bytes() or b"GPL-3.0" in (dist / name).read_bytes()
              and name.endswith(".js")]
    check("no-gpl-runtime-in-assets", not leaked, str(leaked))
    check("relay-methods-unchanged", set(relay.METHODS) == {
        "eth_chainId", "web3_clientVersion", "eth_blockNumber", "eth_maxPriorityFeePerGas", "eth_getBlockByNumber", "eth_getCode",
        "eth_getStorageAt", "eth_call", "eth_estimateGas", "eth_getTransactionCount", "eth_getTransactionByHash",
        "eth_getTransactionReceipt", "eth_getBalance"})
    check("reader-selectors-unchanged", relay.CALL_SELECTORS | relay.KEY_CHANGE_SELECTORS == {
        "0x481286e6", "0x8da5cb5b", "0x1c03010a", "0xd37aec92", "0xb0d691fe", "0x2ffeaad6", "0x35567e1a", "0x70a08231"})
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), base.Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    port = base.free_port()
    server = base.start(port, upstream.server_address[1])
    try:
        check("server-ready", server.poll() is None, "serve.py did not start")
        status, headers, body = base.request(port, "GET", "/prefund.html")
        check("prefund-page", status == 200 and "前払い残高を入金".encode() in body and b'src="prefund.js"' in body, str(status))
        check("prefund-csp", headers.get("Content-Security-Policy") == DEPLOYMENT_CSP, headers.get("Content-Security-Policy"))
        check("prefund-no-store", headers.get("Cache-Control") == "no-store")
        status, headers, _ = base.request(port, "GET", "/prefund.js")
        check("prefund-js", status == 200 and headers.get("Content-Security-Policy") == DEPLOYMENT_CSP, str(status))
        key_page = base.request(port, "GET", "/key-change.html")[2]
        check("nav key->prefund", b'id="prefund-link" class="choice" href="prefund.html" hidden' in key_page)
        check("nav prefund->key", b'id="back-link" class="choice" href="key-change.html"' in body
              and b'href="key-change.html">' in body)
        check("no-url-authority", b"prefund.html?" not in key_page and b"prefund.html#" not in key_page
              and b"key-change.html?" not in body and b"key-change.html#" not in body)
        for path in ("/prefund.html?authority=x", "/prefund.html/"):
            check(f"no-alias {path}", base.request(port, "GET", path)[0] == 404)
        before = len(base.Upstream.seen)
        positives = {
            "chainId": rpc("eth_chainId", []),
            "block-latest": rpc("eth_getBlockByNumber", ["latest", False]),
            "block-exact": rpc("eth_getBlockByNumber", ["0x5b21f24", False]),
            "entrypoint-code-at-B": rpc("eth_getCode", [ENTRYPOINT, "0x5b21f24"]),
            "deposit-at-B": rpc("eth_call", [{"to": ENTRYPOINT, "data": BALANCE_OF}, "0x5b21f24"]),
            "wallet-balance-at-B": rpc("eth_getBalance", [ACCOUNT, "0x5b21f24"]),
            "pending-nonce": rpc("eth_getTransactionCount", [ACCOUNT, "pending"]),
            "transaction": rpc("eth_getTransactionByHash", ["0x" + "ab" * 32]),
            "receipt": rpc("eth_getTransactionReceipt", ["0x" + "ab" * 32]),
        }
        for name, item in positives.items():
            status, _, response = base.request(port, "POST", "/rpc", item)
            check(f"forward {name}", status == 200 and json.loads(response)["id"] == 7, f"{status} {response[:80]}")
        check("forwarded-count", len(base.Upstream.seen) - before == len(positives))
        before = len(base.Upstream.seen)
        forbidden = {
            "sendTransaction-deposit": rpc("eth_sendTransaction", [{"from": ACCOUNT, "to": ENTRYPOINT, "data": DEPOSIT_TO,
                                                                    "value": "0x1"}]),
            "sendRaw": rpc("eth_sendRawTransaction", ["0x02"]),
            "depositTo-call": rpc("eth_call", [{"to": ENTRYPOINT, "data": DEPOSIT_TO}, "latest"]),
            "depositTo-call-value": rpc("eth_call", [{"to": ENTRYPOINT, "data": DEPOSIT_TO, "value": "0x1"}, "latest"]),
            "withdrawTo-call": rpc("eth_call", [{"to": ENTRYPOINT, "data": "0x205c2878" + "00" * 64}, "latest"]),
            "estimate-deposit": rpc("eth_estimateGas", [{"from": ACCOUNT, "to": ENTRYPOINT, "data": DEPOSIT_TO,
                                                         "value": "0x1"}, "latest"]),
            "balance-latest": rpc("eth_getBalance", [ACCOUNT, "latest"]),
            "code-newline": rpc("eth_getCode", [ENTRYPOINT, "0x10\n"]),
            "nonce-newline": rpc("eth_getTransactionCount", [ACCOUNT, "pending\n"]),
            "accounts": rpc("eth_accounts", []),
            "requestAccounts": rpc("eth_requestAccounts", []),
            "sign": rpc("eth_sign", [ACCOUNT, "0x00"]),
            "signTypedData": rpc("eth_signTypedData_v4", [ACCOUNT, "{}"]),
            "impersonate": rpc("anvil_impersonateAccount", [ACCOUNT]),
            "setBalance": rpc("anvil_setBalance", [ACCOUNT, "0x1"]),
            "getLogs": rpc("eth_getLogs", [{"address": ENTRYPOINT}]),
            "switchChain": rpc("wallet_switchEthereumChain", [{"chainId": "0x89"}]),
        }
        for name, item in forbidden.items():
            status, _, _ = base.request(port, "POST", "/rpc", item)
            check(f"reject {name}", status == 403, str(status))
        check("nothing-forwarded", len(base.Upstream.seen) == before, f"{len(base.Upstream.seen) - before} forwarded")
    finally:
        server.terminate()
        server.communicate(timeout=10)
    upstream.shutdown()
    summary = {"suite": "check-prefund-server", "checks": len(base.results), "failed": len(base.failures),
               "results": base.results}
    print(json.dumps(summary, ensure_ascii=False))
    return 1 if base.failures else 0


if __name__ == "__main__":
    sys.exit(main())
