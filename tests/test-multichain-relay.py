"""Real loopback HTTP checks of serve.py's exact read-only chain routes (stdlib only).

The production make_handler serves on an ephemeral 127.0.0.1 port and forwards to four DISTINCT recording loopback
upstreams (one per route). Every assertion inspects what each upstream actually received: method, target route and
payload. Public RPC endpoints are never contacted; these doubles are not chain evidence.

    python3 web/registration/tests/test-multichain-relay.py [--report PATH]
"""
import importlib.util
import json
import os
import socket
import socketserver
import sys
import threading
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("relay", Path(__file__).resolve().parents[1] / "serve.py")
relay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relay)

# Independently restated design routes: path -> chain ID (Polygon keeps /rpc).
ROUTES = {"/rpc": 137, "/rpc/1": 1, "/rpc/8453": 8453, "/rpc/84532": 84532}
ACCOUNT = "0x" + "11" * 20
SAFE = "0x" + "33" * 20


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # Skip HTTPServer's reverse-DNS socket.getfqdn(host): it can stall each loopback listener on a host with
        # restricted DNS.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Upstream:
    """One recording loopback JSON-RPC upstream; `mode` selects an answer or a failure."""

    def __init__(self, chain, mode="ok", redirect=None):
        self.chain, self.mode, self.redirect = chain, mode, redirect
        self.seen = []
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                upstream.seen.append({"path": self.path, "request": request})
                if upstream.mode == "http-500":
                    return self.answer(500, b"{}")
                if upstream.mode == "redirect":
                    self.send_response(307)
                    self.send_header("Location", upstream.redirect)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return None
                if upstream.mode == "malformed":
                    return self.answer(200, b"not json")
                if upstream.mode == "oversize":
                    return self.answer(200, b'{"x":"' + b"0" * (relay.MAX_RESPONSE + 1) + b'"}')
                answer_id = request["id"] + 1 if upstream.mode == "mismatched-id" else request["id"]
                return self.answer(200, json.dumps({"jsonrpc": "2.0", "id": answer_id,
                                                    "result": hex(upstream.chain)}).encode())

            def answer(self, status, body):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = Server(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/upstream-{chain}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


def closed_url():
    """A reserved-then-released loopback port: nothing listens there."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{probe.getsockname()[1]}/closed"


def rpc(method, params, request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def call(to, data, block="0x10"):
    return rpc("eth_call", [{"to": to, "data": data}, block])


def simulation():
    """An independently encoded native CALL simulation admitted by the existing allowlist (nonpersistent)."""
    words = [int("55" * 20, 16), 1, 320, 0, 0, 0, 0, 0, 0, 352, 0, 65]
    data = "0x6a761202" + "".join(f"{n:064x}" for n in words) + "44" * 65 + "00" * 31
    return rpc("eth_call", [{"from": "0x" + "77" * 20, "to": SAFE, "value": "0x0", "data": data}, "0x64"])


# Reads the existing validator admits; every configured route must forward them unchanged.
ADMITTED = {
    "chain-id": rpc("eth_chainId", []),
    "client-version": rpc("web3_clientVersion", []),
    "block-number": rpc("eth_blockNumber", []),
    "priority-fee": rpc("eth_maxPriorityFeePerGas", []),
    "block": rpc("eth_getBlockByNumber", ["latest", False]),
    "code": rpc("eth_getCode", [ACCOUNT, "0x10"]),
    "storage": rpc("eth_getStorageAt", [ACCOUNT, "0x" + "00" * 32, "0x10"]),
    "owner": call(ACCOUNT, "0x8da5cb5b"),
    "entry-point": call(ACCOUNT, "0xb0d691fe"),
    "nonce": call(relay.ENTRYPOINT, "0x35567e1a" + "00" * 12 + ACCOUNT[2:] + "00" * 32),
    "deposit": call(relay.ENTRYPOINT, "0x70a08231" + "00" * 12 + ACCOUNT[2:]),
    "estimate-deploy": rpc("eth_estimateGas", [{"from": ACCOUNT, "to": relay.FACTORY, "data": "0x4af63f02" + "00" * 64,
                                                "value": "0x0"}, "latest"]),
    "transaction-count": rpc("eth_getTransactionCount", [ACCOUNT, "pending"]),
    "transaction": rpc("eth_getTransactionByHash", ["0x" + "22" * 32]),
    "receipt": rpc("eth_getTransactionReceipt", ["0x" + "22" * 32]),
    "balance": rpc("eth_getBalance", [ACCOUNT, "0x10"]),
    "native-simulation": simulation(),
}
# Writes, signing, wallet methods, unknown selectors, batches and malformed shapes never reach any upstream.
FORBIDDEN = {
    "send-raw": rpc("eth_sendRawTransaction", ["0x00"]),
    "send": rpc("eth_sendTransaction", [{"from": ACCOUNT, "to": ACCOUNT}]),
    "sign": rpc("eth_sign", [ACCOUNT, "0x00"]),
    "personal-sign": rpc("personal_sign", ["0x00", ACCOUNT]),
    "typed-sign": rpc("eth_signTypedData_v4", [ACCOUNT, "{}"]),
    "accounts": rpc("eth_accounts", []),
    "wallet": rpc("wallet_addEthereumChain", [{"chainId": "0x1"}]),
    "trace": rpc("debug_traceCall", [{"to": ACCOUNT, "data": "0x"}, "latest"]),
    "filter": rpc("eth_newFilter", [{}]),
    "transfer-selector": call(ACCOUNT, "0xa9059cbb" + "00" * 64),
    "call-with-from": rpc("eth_call", [{"from": ACCOUNT, "to": ACCOUNT, "data": "0x8da5cb5b"}, "0x10"]),
    "estimate-other-target": rpc("eth_estimateGas", [{"from": ACCOUNT, "to": ACCOUNT, "data": "0x4af63f02",
                                                      "value": "0x0"}, "latest"]),
    "balance-latest": rpc("eth_getBalance", [ACCOUNT, "latest"]),
    "code-bad-address": rpc("eth_getCode", ["0x1234", "0x10"]),
    "unknown-member": {**rpc("eth_chainId", []), "chainId": "0x1"},
    "chain-param": rpc("eth_chainId", ["0x2105"]),
    "jsonrpc-1": {**rpc("eth_chainId", []), "jsonrpc": "1.0"},
    "batch": [rpc("eth_chainId", []), rpc("eth_chainId", [], 2)],
}


class RelayHarness:
    """The production handler on an ephemeral loopback port, bound before the handler is constructed."""

    def __init__(self, upstream_url, chain_upstreams=None, keyword=True):
        self.server = Server(("127.0.0.1", 0), BaseHTTPRequestHandler)
        self.port = self.server.server_port
        self.host = f"127.0.0.1:{self.port}"
        self.origin = f"http://{self.host}"
        if keyword:
            handler = relay.make_handler({}, self.host, self.origin, upstream_url, chain_upstreams=chain_upstreams)
        else:
            handler = relay.make_handler({}, self.host, self.origin, upstream_url)
        self.server.RequestHandlerClass = handler
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def request(self, method, path, body=None, origin="default", host=None, content_type="application/json"):
        payload = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
        connection = HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.putrequest(method, path, skip_host=True)
            connection.putheader("Host", host or self.host)
            if origin is not None:
                connection.putheader("Origin", self.origin if origin == "default" else origin)
            if content_type is not None:
                connection.putheader("Content-Type", content_type)
            connection.putheader("Content-Length", str(len(payload or b"")))
            connection.endheaders(payload)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def raw(self, data):
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(data)
            return int(sock.recv(64).split(b" ")[1])

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


class MultichainRelayTests(unittest.TestCase):
    def start(self, modes=None, redirect_to=None, keyword=True, mapping=True, closed=None):
        """Distinct recording upstreams per chain and the handler over them; `closed` names a chain with none."""
        self.upstreams = {}
        for chain in ROUTES.values():
            if chain == closed:
                continue
            mode = (modes or {}).get(chain, "ok")
            target = self.upstreams[redirect_to].url if mode == "redirect" else None
            self.upstreams[chain] = Upstream(chain, mode, target)
            self.addCleanup(self.upstreams[chain].close)
        urls = {chain: upstream.url for chain, upstream in self.upstreams.items()}
        if closed is not None:
            urls[closed] = closed_url()
        chain_upstreams = {chain: urls[chain] for chain in (1, 8453, 84532)} if mapping else None
        self.relay = RelayHarness(urls[137], chain_upstreams, keyword=keyword)
        self.addCleanup(self.relay.close)
        return self.relay

    def seen(self):
        return {chain: list(upstream.seen) for chain, upstream in self.upstreams.items()}

    def assertNothingForwarded(self, label=""):
        self.assertEqual({chain: items for chain, items in self.seen().items() if items}, {}, label)

    def testExactRoutesAndDistinctUpstreams(self):
        self.assertEqual(relay.CHAIN_ROUTES, {"/rpc/1": 1, "/rpc/8453": 8453, "/rpc/84532": 84532})
        server = self.start()
        expected = {chain: [] for chain in ROUTES.values()}
        for path, chain in ROUTES.items():
            for request_id, request in ((chain, rpc("eth_chainId", [], chain)),
                                        (chain + 1, rpc("eth_getCode", [ACCOUNT, "0x10"], chain + 1))):
                status, body = server.request("POST", path, request)
                self.assertEqual(status, 200, path)
                self.assertEqual(json.loads(body), {"jsonrpc": "2.0", "id": request_id, "result": hex(chain)}, path)
                expected[chain].append({"path": f"/upstream-{chain}", "request": request})
        # Each route reached exactly its own upstream with the validated payload, and no other.
        self.assertEqual(self.seen(), expected)

        # The existing positional caller keeps /rpc only; the added routes are unavailable, never Polygon.
        legacy = self.start(keyword=False)
        for path in ("/rpc/1", "/rpc/8453", "/rpc/84532"):
            self.assertEqual(legacy.request("POST", path, rpc("eth_chainId", []))[0], 404, path)
        self.assertNothingForwarded("legacy added routes")
        self.assertEqual(legacy.request("POST", "/rpc", rpc("eth_chainId", []))[0], 200)
        self.assertEqual([len(items) for chain, items in sorted(self.seen().items())], [0, 1, 0, 0])
        unavailable = self.start(mapping=False)
        self.assertEqual(unavailable.request("POST", "/rpc/8453", rpc("eth_chainId", []))[0], 404)
        self.assertNothingForwarded("chain_upstreams=None")

        # Only the exact complete mapping of integer chain IDs is admitted.
        good = {1: "http://127.0.0.1:9/a", 8453: "http://127.0.0.1:9/b", 84532: "http://127.0.0.1:9/c"}
        for bad in ({}, {**good, 137: "http://127.0.0.1:9/d"}, {1: good[1], 8453: good[8453]},
                    {"1": good[1], 8453: good[8453], 84532: good[84532]},
                    {True: good[1], 8453: good[8453], 84532: good[84532]},
                    {**good, 1: None}, [(1, good[1])]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                relay.make_handler({}, "h", "o", "http://127.0.0.1:9/p", chain_upstreams=bad)

        # Operator mapping: fixed environment names and defaults; an invalid value is refused without echoing it.
        self.assertEqual(relay.operator_chain_upstreams({}), {
            1: "https://eth.drpc.org", 8453: "https://base-rpc.publicnode.com",
            84532: "https://base-sepolia-rpc.publicnode.com"})
        environ = {"ETHEREUM_RPC_URL": "http://10.0.0.1:8545", "BASE_RPC_URL": "https://base.example/rpc",
                   "BASE_SEPOLIA_RPC_URL": "http://127.0.0.1:8546/x", "POLYGON_RPC_URL": "https://ignored"}
        self.assertEqual(relay.operator_chain_upstreams(environ), {
            1: "http://10.0.0.1:8545", 8453: "https://base.example/rpc", 84532: "http://127.0.0.1:8546/x"})
        for name in ("ETHEREUM_RPC_URL", "BASE_RPC_URL", "BASE_SEPOLIA_RPC_URL"):
            for value in ("ftp://secret.example", "https://secret.example/?key=1", "https://secret example",
                          "secret.example", "https://secret.example/#x"):
                with self.assertRaises(SystemExit) as raised:
                    relay.operator_chain_upstreams({name: value})
                self.assertIn(name, str(raised.exception))
                self.assertNotIn("secret", str(raised.exception))

    def testUnknownAndMalformedRoutesRefused(self):
        server = self.start()
        paths = ["/rpc/137", "/rpc/2", "/rpc/0", "/rpc/1/", "/rpc/1?", "/rpc/1?chain=8453", "/rpc?chain=1",
                 "/rpc/%31", "/rpc/01", "/rpc//1", "//rpc/1", "/rpc/1/..", "/rpc/../rpc/1", "/RPC/1", "/rpc/1;x",
                 "/rpc/1%2F", "//rpc", "/rpc/0x1", "/rpc/0x2105", "/rpc/base", "/rpc/ethereum", "/rpc/8453/rpc",
                 "/rpc/845320", "/rpc/84532/", "/rpc/1#x", "/x/rpc/1", "/upstream-1"]
        for path in paths:
            for request in (rpc("eth_chainId", []), rpc("eth_sendRawTransaction", ["0x00"])):
                self.assertEqual(server.request("POST", path, request)[0], 404, path)
        self.assertNothingForwarded("unknown routes")
        # Routing input inside the request is rejected by the unchanged validator; a header selects nothing.
        for request in (FORBIDDEN["unknown-member"], FORBIDDEN["chain-param"],
                        {**rpc("eth_chainId", []), "route": "/rpc/1"}):
            self.assertEqual(server.request("POST", "/rpc", request)[0], 403)
            self.assertEqual(server.request("POST", "/rpc/8453", request)[0], 403)
        self.assertNothingForwarded("body routing input")
        connection = HTTPConnection("127.0.0.1", server.port, timeout=10)
        try:
            body = json.dumps(rpc("eth_chainId", [], 5))
            connection.request("POST", "/rpc", body=body, headers={
                "Origin": server.origin, "Content-Type": "application/json", "X-Chain-Id": "8453",
                "X-Forwarded-Path": "/rpc/8453"})
            response = connection.getresponse()
            self.assertEqual((response.status, json.loads(response.read())["result"]), (200, hex(137)))
        finally:
            connection.close()
        self.assertEqual({chain: len(items) for chain, items in self.seen().items()},
                         {137: 1, 1: 0, 8453: 0, 84532: 0})

    def testUnchangedReadOnlyAllowlist(self):
        for name, request in ADMITTED.items():
            self.assertIsNotNone(relay.validate_rpc(json.dumps(request)), f"corpus read {name} not admitted")
        for name, request in FORBIDDEN.items():
            self.assertIsNone(relay.validate_rpc(json.dumps(request)), f"corpus refusal {name} admitted")
        server = self.start()
        for path, chain in ROUTES.items():
            before = self.seen()
            for name, request in FORBIDDEN.items():
                self.assertEqual(server.request("POST", path, request)[0], 403, f"{path} {name}")
            self.assertEqual(self.seen(), before, f"{path}: a refused request reached an upstream")
            for name, request in ADMITTED.items():
                status, body = server.request("POST", path, request)
                self.assertEqual((status, json.loads(body)["result"]), (200, hex(chain)), f"{path} {name}")
            forwarded = self.seen()[chain][len(before[chain]):]
            # Exactly the validator's normalized object for each admitted read, in order, on this route only.
            self.assertEqual([item["request"] for item in forwarded],
                             [relay.validate_rpc(json.dumps(request)) for request in ADMITTED.values()], path)
            self.assertEqual({other: items for other, items in self.seen().items() if other != chain},
                             {other: items for other, items in before.items() if other != chain}, path)
        methods = {item["request"]["method"] for items in self.seen().values() for item in items}
        self.assertFalse({method for method in methods if method.startswith(("eth_send", "eth_sign", "personal_"))})

    def testHostOriginAndBodyBounds(self):
        server = self.start()
        for path in ROUTES:
            valid = rpc("eth_chainId", [])
            self.assertEqual(server.request("POST", path, valid, host="evil.example")[0], 403, path)
            self.assertEqual(server.request("POST", path, valid, origin="https://evil.example")[0], 403, path)
            self.assertEqual(server.request("POST", path, valid, origin=relay.ALLOWED_ORIGIN)[0], 403, path)
            self.assertEqual(server.request("POST", path, valid, origin=None)[0], 403, path)
            self.assertEqual(server.request("POST", path, valid, content_type="text/plain")[0], 415, path)
            self.assertEqual(server.request("POST", path, valid, content_type=None)[0], 415, path)
            self.assertEqual(server.request("POST", path, b"")[0], 413, path)
            self.assertEqual(server.request("POST", path, b"{" + b" " * relay.MAX_REQUEST + b"}")[0], 413, path)
            self.assertEqual(server.request("POST", path, b"not json")[0], 403, path)
            self.assertEqual(server.request("GET", path)[0], 404, path)
            self.assertEqual(server.request("GET", path, host="evil.example")[0], 403, path)
            for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
                self.assertEqual(server.request(method, path, valid)[0], 405, f"{method} {path}")
            no_length = (f"POST {path} HTTP/1.1\r\nHost: {server.host}\r\nOrigin: {server.origin}\r\n"
                         "Content-Type: application/json\r\nConnection: close\r\n\r\n").encode()
            self.assertEqual(server.raw(no_length), 411, path)
        self.assertNothingForwarded("bounds")

    def testUpstreamFailureHasNoCrossChainFallback(self):
        for mode in ("http-500", "malformed", "mismatched-id", "oversize", "redirect", "closed"):
            server = self.start(modes={8453: mode}, redirect_to=137, closed=8453 if mode == "closed" else None)
            status, body = server.request("POST", "/rpc/8453", rpc("eth_chainId", [], 9))
            self.assertEqual(status, 502, mode)
            self.assertEqual(set(json.loads(body)), {"error"}, mode)
            seen = self.seen()
            # The failing upstream got exactly the one request (no retry); no other chain was tried or redirected to.
            self.assertEqual(len(seen.get(8453, [])), 0 if mode == "closed" else 1, mode)
            self.assertEqual({chain: len(items) for chain, items in seen.items() if chain != 8453},
                             {137: 0, 1: 0, 84532: 0}, mode)
            # Other routes keep their own upstreams after the failure.
            self.assertEqual(server.request("POST", "/rpc/1", rpc("eth_chainId", [], 10))[0], 200, mode)
            self.assertEqual(len(self.seen()[1]), 1, mode)
            self.assertEqual(len(self.seen()[137]), 0, mode)


class Recorder(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = {}

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes.setdefault(test._testMethodName, []).append("passed")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes.setdefault(test._testMethodName, []).append("failed")

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes.setdefault(getattr(test, "_testMethodName", str(test)), []).append("error")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes.setdefault(test._testMethodName, []).append("skipped")


def main(argv):
    report = None
    if "--report" in argv:
        report = Path(argv[argv.index("--report") + 1])
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(MultichainRelayTests)
    result = unittest.TextTestRunner(resultclass=Recorder, verbosity=2).run(suite)
    if report is not None:
        report.write_text(json.dumps({
            "suite": "test-multichain-relay", "run_id": os.environ.get("HYBRID_MULTICHAIN_READ_RUN_ID"),
            "tests": result.outcomes, "testsRun": result.testsRun, "successful": result.wasSuccessful(),
        }, indent=2, sort_keys=True) + "\n")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
