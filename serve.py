"""Static deployment Web with a read-only same-origin Polygon JSON-RPC relay.

Serves only the built assets listed (with SHA-256) in dist/asset-manifest.json plus a fixed public
/config.json, and forwards one allowlisted read-only JSON-RPC object per request to the operator's fixed
POLYGON_RPC_URL. The exact read-only chain routes /rpc/1, /rpc/8453 and /rpc/84532 forward under the same
allowlist and bounds to the operator's fixed ETHEREUM_RPC_URL, BASE_RPC_URL and BASE_SEPOLIA_RPC_URL; request
data never selects an upstream and a failure never falls back to another chain. It holds no key, never submits,
signs or unlocks, follows no redirect and logs nothing.
"""
import hashlib
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
PROXY_SHA256 = "103c4d3815dd2472c4a257bcd94e8b8b49ce39de453add9d8285b749bb926aa7"
ALLOWED_ORIGIN = "https://p256-signer.tumf.dev"
PAGES_ORIGIN = "https://p256-signer.tumf.dev"
FACTORY = "0x69aa2f9fe1572f1b640e1bbc512f5c3a734fc77c"
ENTRYPOINT = "0x0000000071727de22e5e9d8baf0edac6f37da032"
MAX_REQUEST = 32768
MAX_RESPONSE = 2_000_000
UPSTREAM_TIMEOUT = 10
UPSTREAM_URL = re.compile(r"https?://[^\s/?#]+(/[^\s?#]*)?")
# The additional exact read-only routes; /rpc stays Polygon. No /rpc/137 alias, query, suffix or body-selected chain.
CHAIN_ROUTES = {"/rpc/1": 1, "/rpc/8453": 8453, "/rpc/84532": 84532}
# Operator environment names and defaults of the added routes' fixed upstreams.
CHAIN_ENVIRONMENT = {1: ("ETHEREUM_RPC_URL", "https://eth.drpc.org"),
                     8453: ("BASE_RPC_URL", "https://base-rpc.publicnode.com"),
                     84532: ("BASE_SEPOLIA_RPC_URL", "https://base-sepolia-rpc.publicnode.com")}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
       "connect-src 'self' https://polygon-bor-rpc.publicnode.com https://ethereum-rpc.publicnode.com https://base-rpc.publicnode.com https://base-sepolia-rpc.publicnode.com wss://relay.walletconnect.com https://relay.walletconnect.com; "
       "base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'")
# Safe approval and key-change pages only: the pinned SignClient's Verify attestation iframe and its endpoints. The
# deployment pages keep CSP byte-identical.
SAFE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "connect-src 'self' https://polygon-bor-rpc.publicnode.com https://ethereum-rpc.publicnode.com https://base-rpc.publicnode.com https://base-sepolia-rpc.publicnode.com wss://relay.walletconnect.com https://relay.walletconnect.com "
            "https://verify.walletconnect.org https://verify.walletconnect.com; "
            "frame-src https://verify.walletconnect.org https://verify.walletconnect.com; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'")
MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".json": "application/json", ".md": "text/markdown; charset=utf-8",
        ".txt": "text/plain; charset=utf-8"}

ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
QUANTITY = re.compile(r"^0x(0|[1-9a-fA-F][0-9a-fA-F]{0,63})$")
HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
DATA = re.compile(r"^0x([0-9a-fA-F]{2}){0,8192}$")
# Read selectors: Factory computeAddress, Hybrid owner/getKeyIdHashesCount/getKey, Factory deploy (estimate only),
# and the Hybrid context reader's entryPoint()/getKeyIdHashes() and EntryPoint getNonce(address,uint192).
CALL_SELECTORS = {"0x481286e6", "0x8da5cb5b", "0x1c03010a", "0xd37aec92", "0xb0d691fe", "0x2ffeaad6", "0x35567e1a"}
DEPLOY_SELECTOR = "0x4af63f02"
# The reader's added selectors have exact full-string shapes: no arguments, or getNonce(sender, key 0) on the pinned
# EntryPoint with a nonzero sender in a zero-padded word.
ZERO_ARG_SELECTORS = {"0xb0d691fe", "0x2ffeaad6"}
GET_NONCE_SELECTOR = "0x35567e1a"
GET_NONCE_CALL = re.compile(r"0x35567e1a0{24}(?!0{40})[0-9a-f]{40}0{64}", re.IGNORECASE)
# Key-change page: EntryPoint balanceOf(address) (the signer deposit) on the pinned EntryPoint only, with exactly one
# nonzero zero-padded address word. It is the only added call selector, kept outside the reviewed reader set; no
# generic eth_call admission.
BALANCE_OF_SELECTOR = "0x70a08231"
KEY_CHANGE_SELECTORS = {BALANCE_OF_SELECTOR}
BALANCE_OF_CALL = re.compile(r"0x70a082310{24}(?!0{40})[0-9a-f]{40}", re.IGNORECASE)
# Safe recovery only; keep the existing reader and key-change allowlists unchanged.
SAFE_RECOVERY_READS = {"0xffa1ad74", "0xa0e67e2b", "0xe75235b8", "0xaffed0e0"}
SAFE_HASH_SELECTOR = "0xd8d11f78"
SAFE_SIGNATURE_SELECTOR = "0x1626ba7e"
SAFE_RECOVERY_SELECTORS = SAFE_RECOVERY_READS | {SAFE_HASH_SELECTOR, SAFE_SIGNATURE_SELECTOR}
# Execution reader: only the sentinel start with pageSize=1 (existing consumers) or exactly pageSize=65 (the bounded
# readExecution page); no page-size range, other start, arbitrary module pagination or eth_call.
SAFE_MODULE_SELECTOR = "0xcc2f8452"
SAFE_MODULE_CALL = SAFE_MODULE_SELECTOR + f"{1:064x}" * 2
SAFE_MODULE_PAGE65_CALL = ("0xcc2f8452" "0000000000000000000000000000000000000000000000000000000000000001"
                           "0000000000000000000000000000000000000000000000000000000000000041")
SAFE_MODULE_CALLS = frozenset({SAFE_MODULE_CALL, SAFE_MODULE_PAGE65_CALL})
SAFE_EXECUTION_SELECTORS = {SAFE_MODULE_SELECTOR}
# Complete native-transfer hash ABI: nonzero padded recipient, uint256 value, data offset 320,
# CALL, uint256 safeTxGas/baseGas, zero reimbursement fields, uint256 nonce, empty data length.
SAFE_HASH_CALL = re.compile(r"0xd8d11f780{24}(?!0{40})[0-9a-f]{40}[0-9a-f]{64}" + f"{320:064x}"
                            + r"0{64}[0-9a-f]{128}0{192}[0-9a-f]{64}0{64}", re.IGNORECASE)
# bytes32 H, bytes offset 64, length 96, exactly three inner-signature words. No extra padding.
SAFE_SIGNATURE_CALL = re.compile(r"0x1626ba7e[0-9a-f]{64}" + f"{64:064x}{96:064x}"
                                 + r"[0-9a-f]{192}", re.IGNORECASE)
SAFE_CSP_PAGES = {"/safe-request.html", "/key-change.html"}


def block_tag(value):
    return value == "latest" or (isinstance(value, str) and QUANTITY.fullmatch(value) is not None)


def native_simulation(params):
    """Bounded native or addOwner CALL only; simulation confers no send authority."""
    if len(params) != 2 or not isinstance(params[1], str) or not re.fullmatch(r"0x(0|[1-9a-f][0-9a-f]{0,15})", params[1]):
        return False
    tx = params[0]
    if not isinstance(tx, dict) or set(tx) != {"from", "to", "value", "data"} or tx["value"] != "0x0":
        return False
    if any(not isinstance(tx[k], str) or not re.fullmatch(r"0x[0-9a-f]{40}", tx[k])
           or int(tx[k], 16) <= 1 for k in ("from", "to")) or tx["from"] == tx["to"]:
        return False
    data = tx["data"]
    if not isinstance(data, str) or not 778 <= len(data) <= 8970 or not re.fullmatch(r"0x6a761202[0-9a-f]+", data):
        return False
    words = [int(data[10 + 64 * i:74 + 64 * i], 16) for i in range(12)]
    recipient, amount, offset, operation, gas, base, price, token, refund, signatures, size, length = words
    if recipient == int(tx["to"], 16):
        # Canonical addOwnerWithThreshold only, never generic Safe self-calls.
        if (amount, offset, operation, gas, base, price, token, refund, signatures, size) != (0, 320, 0, 0, 0, 0, 0, 0, 448, 68):
            return False
        inner = data[714:906]
        if len(data) < 970 or inner[:8] != "0d582f13" or inner[136:] != "0" * 56:
            return False
        owner, threshold = int(inner[8:72], 16), int(inner[72:136], 16)
        if not 1 < owner < 2 ** 160 or owner == recipient or not 1 <= threshold <= 8:
            return False
        length = int(data[906:970], 16)
        if length % 65 or not 65 <= length <= 7 * 65:
            return False
        end = 970 + length * 2
        padded = 970 + ((length + 31) // 32) * 64
        if len(data) != padded or data[end:] != "0" * (padded - end):
            return False
        # Shape only: current EOA membership, recovery and threshold remain product/Safe checks.
        for start in range(970, end, 130):
            r, s, v = int(data[start:start + 64], 16), int(data[start + 64:start + 128], 16), int(data[start + 128:start + 130], 16)
            if not 0 < r < 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 \
                    or not 0 < s <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0 or v not in (27, 28):
                return False
        return True
    if not 1 < recipient < 2 ** 160 or amount == 0 \
            or (offset, operation, gas, base, price, token, refund, signatures, size) != (320, 0, 0, 0, 0, 0, 0, 352, 0) \
            or not 65 <= length <= 4096:
        return False
    end = 778 + length * 2
    padded = 778 + ((length + 31) // 32) * 64
    return len(data) == padded and data[end:] == "0" * (padded - end)


def valid_call(tx, estimate=False):
    if not isinstance(tx, dict):
        return False
    keys = set(tx)
    if estimate:
        return keys == {"from", "to", "data", "value"} and isinstance(tx["from"], str) and ADDRESS.fullmatch(tx["from"]) \
            and isinstance(tx["to"], str) and tx["to"].lower() == FACTORY and isinstance(tx["data"], str) \
            and DATA.fullmatch(tx["data"]) and tx["data"].lower().startswith(DEPLOY_SELECTOR) and tx["value"] == "0x0"
    return keys == {"to", "data"} and isinstance(tx["to"], str) and ADDRESS.fullmatch(tx["to"]) \
        and isinstance(tx["data"], str) and DATA.fullmatch(tx["data"]) and len(tx["data"]) <= 4 * 1024 \
        and tx["data"][:10].lower() in CALL_SELECTORS | KEY_CHANGE_SELECTORS | SAFE_RECOVERY_SELECTORS | SAFE_EXECUTION_SELECTORS \
        and (tx["data"][:10].lower() != "0x481286e6" or tx["to"].lower() == FACTORY) \
        and valid_reader_call(tx["to"], tx["data"])


def valid_reader_call(to, data):
    """Full-string shapes of the context reader's added selectors; every other allowed selector is unchanged."""
    selector = data[:10].lower()
    if selector in ZERO_ARG_SELECTORS | SAFE_RECOVERY_READS:
        return ADDRESS.fullmatch(to) is not None and len(data) == 10
    if selector == SAFE_MODULE_SELECTOR:
        return data.lower() in SAFE_MODULE_CALLS
    if selector == GET_NONCE_SELECTOR:
        return to.lower() == ENTRYPOINT and GET_NONCE_CALL.fullmatch(data) is not None
    if selector == BALANCE_OF_SELECTOR:
        return to.lower() == ENTRYPOINT and BALANCE_OF_CALL.fullmatch(data) is not None
    if selector == SAFE_HASH_SELECTOR:
        return SAFE_HASH_CALL.fullmatch(data) is not None and "0x" + data[34:74].lower() != to.lower()
    if selector == SAFE_SIGNATURE_SELECTOR:
        return SAFE_SIGNATURE_CALL.fullmatch(data) is not None
    return True


def is_address(value):
    return isinstance(value, str) and ADDRESS.fullmatch(value) is not None


def is_hash(value):
    return isinstance(value, str) and HASH.fullmatch(value) is not None


# Exact read-only method allowlist with per-method parameter shapes.
METHODS = {
    "eth_chainId": lambda p: p == [],
    # Client identity read: the fork-only execution gate requires an anvil answer; no parameters, no state.
    "web3_clientVersion": lambda p: p == [],
    "eth_blockNumber": lambda p: p == [],
    "eth_maxPriorityFeePerGas": lambda p: p == [],
    "eth_getBlockByNumber": lambda p: len(p) == 2 and block_tag(p[0]) and isinstance(p[1], bool),
    "eth_getCode": lambda p: len(p) == 2 and is_address(p[0]) and block_tag(p[1]),
    "eth_getStorageAt": lambda p: len(p) == 3 and is_address(p[0]) and is_hash(p[1]) and block_tag(p[2]),
    "eth_call": lambda p: native_simulation(p) or (len(p) == 2 and valid_call(p[0]) and block_tag(p[1])),
    "eth_estimateGas": lambda p: len(p) == 2 and valid_call(p[0], estimate=True) and block_tag(p[1]),
    "eth_getTransactionCount": lambda p: len(p) == 2 and is_address(p[0]) and (p[1] == "pending" or block_tag(p[1])),
    "eth_getTransactionByHash": lambda p: len(p) == 1 and is_hash(p[0]),
    "eth_getTransactionReceipt": lambda p: len(p) == 1 and is_hash(p[0]),
    # Key-change executor balance at the inspection block B: an exact block number, never a tag.
    "eth_getBalance": lambda p: len(p) == 2 and isinstance(p[0], str) and ADDRESS.fullmatch(p[0]) is not None
    and isinstance(p[1], str) and QUANTITY.fullmatch(p[1]) is not None,
}


def validate_rpc(body):
    """The parsed single JSON-RPC object, or None. Batches, unknown members and other methods are rejected."""
    try:
        request = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(request, dict) or not set(request) <= {"jsonrpc", "id", "method", "params"} \
            or request.get("jsonrpc") != "2.0" or "method" not in request:
        return None
    request_id = request.get("id")
    if not (isinstance(request_id, int) and not isinstance(request_id, bool) and 0 <= request_id < 2 ** 53) \
            and not (isinstance(request_id, str) and len(request_id) <= 64):
        return None
    params = request.get("params", [])
    check = METHODS.get(request["method"]) if isinstance(request["method"], str) else None
    if check is None or not isinstance(params, list) or not check(params):
        return None
    return {"jsonrpc": "2.0", "id": request_id, "method": request["method"], "params": params}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise URLError("redirect refused")


def load_assets():
    """Startup checks: pinned proxy artifact, built manifest and every listed asset hash."""
    proxy = (ROOT / "vendor/proxy.json").read_bytes()
    if hashlib.sha256(proxy).hexdigest() != PROXY_SHA256:
        raise SystemExit("refusing to start: vendor/proxy.json SHA-256 changed")
    manifest = json.loads((DIST / "asset-manifest.json").read_text())
    if manifest.get("proxySHA256") != PROXY_SHA256:
        raise SystemExit("refusing to start: build was not made from the pinned proxy artifact")
    assets = {}
    for name, digest in manifest["files"].items():
        path = (DIST / name).resolve()
        if DIST.resolve() not in path.parents or not path.is_file():
            raise SystemExit(f"refusing to start: missing asset {name}")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise SystemExit(f"refusing to start: asset {name} changed after build")
        assets["/" + name] = (data, MIME.get(path.suffix, "application/octet-stream"))
    assets["/"] = assets["/index.html"]
    license_path = "/licenses/walletconnect-LICENSE.md"
    if assets.get(license_path, (None,))[0] != (ROOT / "vendor/walletconnect-LICENSE.md").read_bytes():
        raise SystemExit("refusing to start: served WalletConnect license differs from vendor copy")
    return assets


def public_config():
    project = os.environ.get("WALLETCONNECT_PROJECT_ID", "")
    return {"walletConnectProjectId": project if re.fullmatch(r"[0-9a-f]{32}", project) else None,
            "allowedDeploymentOrigin": (os.environ.get("REGISTRATION_CONFIG_ORIGIN")
                 if os.environ.get("REGISTRATION_CONFIG_ORIGIN") in (ALLOWED_ORIGIN, "https://p256-signer.mini.tumf.dev")
                 else ALLOWED_ORIGIN)}


def operator_chain_upstreams(environ):
    """The complete operator mapping for the added routes; each value must be a plain http(s) URL (never printed)."""
    upstreams = {}
    for chain, (name, default) in CHAIN_ENVIRONMENT.items():
        value = environ.get(name, default)
        if not UPSTREAM_URL.fullmatch(value):
            raise SystemExit(f"refusing to start: {name} must be a plain http(s) URL")
        upstreams[chain] = value
    return upstreams


def make_handler(assets, public_host, public_origin, upstream, *, chain_upstreams=None):
    """`/rpc` forwards to `upstream`; `chain_upstreams` maps exactly the chain IDs 1, 8453 and 84532 to their fixed
    upstreams, and None leaves those routes unavailable (404), never Polygon."""
    if chain_upstreams is not None and (
            not isinstance(chain_upstreams, dict) or any(type(chain) is not int for chain in chain_upstreams)
            or set(chain_upstreams) != set(CHAIN_ROUTES.values())
            or not all(isinstance(url, str) for url in chain_upstreams.values())):
        raise ValueError("chain_upstreams must map exactly the chain IDs 1, 8453 and 84532 to upstream URLs")
    routes = {"/rpc": upstream}
    if chain_upstreams is not None:
        routes.update({path: chain_upstreams[chain] for path, chain in CHAIN_ROUTES.items()})
    config = json.dumps(public_config(), separators=(",", ":")).encode()
    opener = build_opener(NoRedirect)

    class Handler(BaseHTTPRequestHandler):
        server_version = "registration"
        sys_version = ""

        def log_message(self, *args):
            # No request logging: paths, bodies and fragments never reach diagnostics.
            pass

        def respond(self, code, data, mime="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", SAFE_CSP if self.path in SAFE_CSP_PAGES else CSP)
            if self.path in routes and self.headers.get("Origin") == PAGES_ORIGIN:
                self.send_header("Access-Control-Allow-Origin", PAGES_ORIGIN)
                self.send_header("Vary", "Origin")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def error(self, code, message):
            self.respond(code, json.dumps({"error": message}).encode())

        def trusted(self):
            origin = self.headers.get("Origin")
            return self.headers.get("Host") == public_host and (origin is None or origin == public_origin)

        def do_GET(self):
            if not self.trusted():
                return self.error(403, "forbidden origin or host")
            if self.path == "/config.json":
                return self.respond(200, config)
            asset = assets.get(self.path)
            if asset is None:
                return self.error(404, "not found")
            self.respond(200, *asset)

        do_HEAD = do_GET

        def do_POST(self):
            if self.headers.get("Host") != public_host or self.headers.get("Origin") not in (public_origin, PAGES_ORIGIN):
                return self.error(403, "forbidden origin or host")
            # Exact route dispatch on the raw request target (the stdlib collapses a leading "//" into self.path),
            # before any forwarding; the rules below apply unchanged to every route.
            target = routes.get(self.path) if self.requestline.split(" ")[1:2] == [self.path] else None
            if target is None:
                return self.error(404, "not found")
            if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
                return self.error(415, "application/json required")
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self.error(411, "length required")
            if not 0 < length <= MAX_REQUEST:
                return self.error(413, "request too large")
            request = validate_rpc(self.rfile.read(length))
            if request is None:
                return self.error(403, "read-only RPC: method or parameters not allowed")
            try:
                with opener.open(Request(target, data=json.dumps(request).encode(),
                                         headers={"Content-Type": "application/json", "User-Agent": "p256-signer-read-relay/1.0"}),
                                 timeout=UPSTREAM_TIMEOUT) as response:
                    body = response.read(MAX_RESPONSE + 1)
            except (HTTPError, URLError, OSError, ValueError):
                return self.error(502, "upstream RPC unavailable")
            if len(body) > MAX_RESPONSE:
                return self.error(502, "upstream response too large")
            try:
                parsed = json.loads(body)
            except ValueError:
                return self.error(502, "upstream response malformed")
            if not isinstance(parsed, dict) or parsed.get("id") != request["id"]:
                return self.error(502, "upstream response malformed")
            self.respond(200, body)

        def do_PUT(self):
            self.error(405, "method not allowed")

        def do_OPTIONS(self):
            if (self.headers.get("Host") != public_host or self.headers.get("Origin") != PAGES_ORIGIN
                    or self.path not in routes or self.requestline.split(" ")[1:2] != [self.path]
                    or self.headers.get("Access-Control-Request-Method") != "POST"
                    or self.headers.get("Access-Control-Request-Headers", "").lower().strip() != "content-type"):
                return self.error(403, "forbidden preflight")
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", PAGES_ORIGIN)
            self.send_header("Access-Control-Allow-Methods", "POST")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Vary", "Origin")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_DELETE = do_PATCH = do_PUT

    return Handler


def main():
    host = os.environ.get("REGISTRATION_HOST", "127.0.0.1")
    port = int(os.environ.get("REGISTRATION_PORT", "18763"))
    public_host = os.environ.get("REGISTRATION_PUBLIC_HOST", f"{host}:{port}")
    public_origin = os.environ.get("REGISTRATION_PUBLIC_ORIGIN", f"http://{public_host}")
    upstream = os.environ.get("POLYGON_RPC_URL", "https://polygon.drpc.org")
    if not UPSTREAM_URL.fullmatch(upstream):
        raise SystemExit("refusing to start: POLYGON_RPC_URL must be a plain http(s) URL")
    chain_upstreams = operator_chain_upstreams(os.environ)
    assets = load_assets()
    server = ThreadingHTTPServer((host, port), make_handler(assets, public_host, public_origin, upstream,
                                                            chain_upstreams=chain_upstreams))
    print(f"ready http://{host}:{server.server_address[1]} (read-only registration Web)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
