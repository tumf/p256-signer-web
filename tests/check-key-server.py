"""Real local HTTP checks of serve.py's key-change additions against a fake read-only upstream on loopback.

Exercises the actual handler (not validate_rpc alone) over the built dist/: the key-change page and its Safe-only
Verify CSP, byte-identical deployment/Safe CSP, reciprocal navigation, the two new bounded reads (EntryPoint
balanceOf(address) and eth_getBalance(address, exact block)) forwarded, and every malformed/foreign/send shape
rejected before forwarding. The pinned reader selector set stays unchanged. Prints one JSON summary line.
"""
import importlib.util
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_server", HERE / "check-server.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
relay_spec = importlib.util.spec_from_file_location("relay", HERE.parent / "serve.py")
relay = importlib.util.module_from_spec(relay_spec)
relay_spec.loader.exec_module(relay)

ACCOUNT = base.ACCOUNT
ENTRYPOINT = base.ENTRYPOINT
BALANCE_OF = "0x70a08231" + "00" * 12 + ACCOUNT[2:]
DEPLOYMENT_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
                  "connect-src 'self' wss://relay.walletconnect.com https://relay.walletconnect.com; "
                  "base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'")
SAFE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "connect-src 'self' wss://relay.walletconnect.com https://relay.walletconnect.com "
            "https://verify.walletconnect.org https://verify.walletconnect.com; "
            "frame-src https://verify.walletconnect.org https://verify.walletconnect.com; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'")
check = base.check
rpc = base.rpc


def check_rpc_boundaries():
    """Exercise the trust boundary without requiring a built dist or any listening service."""
    cases = [
        ("eth_call", [{"to": ENTRYPOINT, "data": BALANCE_OF}, "0x10"], [(1, "0x10\n")]),
        ("eth_getBlockByNumber", ["0x10", False], [(0, "0x10\n")]),
        ("eth_getCode", [ACCOUNT, "latest"], [(0, ACCOUNT + "\n")]),
        ("eth_getStorageAt", [ACCOUNT, "0x" + "ab" * 32, "0x10"], [(1, "0x" + "ab" * 32 + "\n")]),
        ("eth_getTransactionReceipt", ["0x" + "ab" * 32], [(0, "0x" + "ab" * 32 + "\n")]),
        ("eth_call", [{"to": ACCOUNT, "data": "0x8da5cb5b"}, "latest"],
         [(0, {"to": ACCOUNT, "data": "0x8da5cb5b\n"}), (0, {"to": ACCOUNT + "\n", "data": "0x8da5cb5b"})]),
        ("eth_estimateGas", [{"from": ACCOUNT, "to": relay.FACTORY, "data": relay.DEPLOY_SELECTOR,
                              "value": "0x0"}, "latest"],
         [(0, {"from": ACCOUNT, "to": relay.FACTORY, "data": relay.DEPLOY_SELECTOR + "\n", "value": "0x0"}),
          (0, {"from": ACCOUNT + "\n", "to": relay.FACTORY, "data": relay.DEPLOY_SELECTOR, "value": "0x0"})]),
    ]
    for method, params, mutations in cases:
        assert relay.validate_rpc(json.dumps(rpc(method, params))) is not None, method
        for index, value in mutations:
            malformed = list(params)
            malformed[index] = value
            check(f"full-string {method} {index} {value!r}",
                  relay.validate_rpc(json.dumps(rpc(method, malformed))) is None)
    failed = {key: value for key, value in base.results.items() if value != "pass"}
    print(json.dumps({"suite": "rpc-boundaries", "checks": len(base.results), "failed": len(failed), "failures": failed}))
    return 1 if failed else 0


def main():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), base.Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    upstream_port = upstream.server_address[1]
    port = base.free_port()
    server = base.start(port, upstream_port)
    try:
        check("server-ready", server.poll() is None, "serve.py did not start")
        status, headers, body = base.request(port, "GET", "/key-change.html")
        check("key-page", status == 200 and "内部鍵の追加・削除".encode() in body
              and b'src="key-change.js"' in body, str(status))
        check("key-page-csp", headers.get("Content-Security-Policy") == SAFE_CSP, headers.get("Content-Security-Policy"))
        for path, csp in (("/", DEPLOYMENT_CSP), ("/index.html", DEPLOYMENT_CSP), ("/safe-request.html", SAFE_CSP),
                          ("/key-change.js", DEPLOYMENT_CSP), ("/config.json", DEPLOYMENT_CSP)):
            status, headers, _ = base.request(port, "GET", path)
            check(f"csp {path}", status == 200 and headers.get("Content-Security-Policy") == csp,
                  f"{status} {headers.get('Content-Security-Policy')}")
        pages = {path: base.request(port, "GET", path)[2] for path in ("/index.html", "/safe-request.html",
                                                                         "/key-change.html")}
        check("nav deployment->key", b'href="key-change.html"' in pages["/index.html"])
        check("nav safe->key", b'href="key-change.html"' in pages["/safe-request.html"])
        check("nav key->deployment", b'href="/"' in pages["/key-change.html"])
        check("nav key->safe", b'href="safe-request.html"' in pages["/key-change.html"])
        check("reader-selectors-unchanged", relay.CALL_SELECTORS == {
            "0x481286e6", "0x8da5cb5b", "0x1c03010a", "0xd37aec92", "0xb0d691fe", "0x2ffeaad6", "0x35567e1a"})
        before = len(base.Upstream.seen)
        positives = {
            "balanceOf": rpc("eth_call", [{"to": ENTRYPOINT, "data": BALANCE_OF}, "0x10"]),
            "balanceOf-upper": rpc("eth_call", [{"to": ENTRYPOINT.upper().replace("0X", "0x"),
                                                 "data": BALANCE_OF.upper().replace("0X", "0x")}, "0x10"]),
            "getBalance": rpc("eth_getBalance", [ACCOUNT, "0x5b21f24"]),
            "receipt": rpc("eth_getTransactionReceipt", ["0x" + "ab" * 32]),
            "transaction": rpc("eth_getTransactionByHash", ["0x" + "ab" * 32]),
        }
        for name, item in positives.items():
            status, _, body = base.request(port, "POST", "/rpc", item)
            check(f"forward {name}", status == 200 and json.loads(body)["id"] == 7, f"{status} {body[:80]}")
        check("forwarded-count", len(base.Upstream.seen) - before == len(positives))
        before = len(base.Upstream.seen)
        forbidden = {
            "balanceOf-other-target": rpc("eth_call", [{"to": ACCOUNT, "data": BALANCE_OF}, "0x10"]),
            "balanceOf-zero": rpc("eth_call", [{"to": ENTRYPOINT, "data": "0x70a08231" + "00" * 32}, "0x10"]),
            "balanceOf-padding": rpc("eth_call", [{"to": ENTRYPOINT, "data": BALANCE_OF[:10] + "01"
                                                   + BALANCE_OF[12:]}, "0x10"]),
            "balanceOf-short": rpc("eth_call", [{"to": ENTRYPOINT, "data": BALANCE_OF[:-2]}, "0x10"]),
            "balanceOf-long": rpc("eth_call", [{"to": ENTRYPOINT, "data": BALANCE_OF + "00"}, "0x10"]),
            "balanceOf-newline": rpc("eth_call", [{"to": ENTRYPOINT, "data": BALANCE_OF + "\n"}, "0x10"]),
            "balanceOf-block-newline": rpc("eth_call", [{"to": ENTRYPOINT, "data": BALANCE_OF}, "0x10\n"]),
            "block-newline": rpc("eth_getBlockByNumber", ["0x10\n", False]),
            "code-address-newline": rpc("eth_getCode", [ACCOUNT + "\n", "latest"]),
            "storage-slot-newline": rpc("eth_getStorageAt", [ACCOUNT, "0x" + "ab" * 32 + "\n", "0x10"]),
            "receipt-hash-newline": rpc("eth_getTransactionReceipt", ["0x" + "ab" * 32 + "\n"]),
            "legacy-call-data-newline": rpc("eth_call", [{"to": ACCOUNT, "data": "0x8da5cb5b\n"}, "latest"]),
            "estimate-data-newline": rpc("eth_estimateGas", [{"from": ACCOUNT, "to": relay.FACTORY,
                                                              "data": relay.DEPLOY_SELECTOR + "\n",
                                                              "value": "0x0"}, "latest"]),
            "estimate-from-newline": rpc("eth_estimateGas", [{"from": ACCOUNT + "\n", "to": relay.FACTORY,
                                                              "data": relay.DEPLOY_SELECTOR,
                                                              "value": "0x0"}, "latest"]),
            "balanceOf-no-arg": rpc("eth_call", [{"to": ENTRYPOINT, "data": "0x70a08231"}, "0x10"]),
            "getUserOpHash": rpc("eth_call", [{"to": ENTRYPOINT, "data": "0x22cdde4c" + "00" * 32}, "0x10"]),
            "handleOps-call": rpc("eth_call", [{"to": ENTRYPOINT, "data": "0x765e827f" + "00" * 64}, "0x10"]),
            "estimate-handleOps": rpc("eth_estimateGas", [{"from": ACCOUNT, "to": ENTRYPOINT, "data": "0x765e827f",
                                                          "value": "0x0"}, "latest"]),
            "getBalance-latest": rpc("eth_getBalance", [ACCOUNT, "latest"]),
            "getBalance-pending": rpc("eth_getBalance", [ACCOUNT, "pending"]),
            "getBalance-no-block": rpc("eth_getBalance", [ACCOUNT]),
            "getBalance-extra": rpc("eth_getBalance", [ACCOUNT, "0x10", "0x1"]),
            "getBalance-bad-address": rpc("eth_getBalance", ["0x1234", "0x10"]),
            "getBalance-address-newline": rpc("eth_getBalance", [ACCOUNT + "\n", "0x10"]),
            "getBalance-block-newline": rpc("eth_getBalance", [ACCOUNT, "0x10\n"]),
            "getBalance-leading-zero": rpc("eth_getBalance", [ACCOUNT, "0x010"]),
            "getBalance-object": rpc("eth_getBalance", [ACCOUNT, {"blockHash": "0x" + "ab" * 32}]),
            "sendTransaction": rpc("eth_sendTransaction", [{"from": ACCOUNT, "to": ENTRYPOINT, "data": "0x765e827f"}]),
            "sendRaw": rpc("eth_sendRawTransaction", ["0x02"]),
            "sendUserOperation": rpc("eth_sendUserOperation", [{}, ENTRYPOINT]),
            "getLogs": rpc("eth_getLogs", [{"address": ENTRYPOINT}]),
            "sign": rpc("eth_signTypedData_v4", [ACCOUNT, "{}"]),
        }
        for name, item in forbidden.items():
            status, _, _ = base.request(port, "POST", "/rpc", item)
            check(f"reject {name}", status == 403, str(status))
        check("nothing-forwarded", len(base.Upstream.seen) == before, f"{len(base.Upstream.seen) - before} forwarded")
    finally:
        server.terminate()
        server.communicate(timeout=10)
    upstream.shutdown()
    summary = {"suite": "check-key-server", "checks": len(base.results), "failed": len(base.failures),
               "results": base.results}
    print(json.dumps(summary, ensure_ascii=False))
    return 1 if base.failures else 0


if __name__ == "__main__":
    sys.exit(check_rpc_boundaries() if sys.argv[1:] == ["--rpc-boundaries"] else main())
