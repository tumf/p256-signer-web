"""Product relay's exact module reads (page 1 and page 65 only); local HTTP doubles, never chain proof."""
import importlib.util
import json
from pathlib import Path
import threading
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

spec = importlib.util.spec_from_file_location("relay", Path(__file__).resolve().parents[1] / "serve.py")
if spec is None or spec.loader is None:
    raise RuntimeError("relay import unavailable")
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
SAFE = "0x" + "33" * 20
CALL = "0xcc2f8452" + f"{1:064x}" * 2  # sentinel, pageSize=1, generated independently by SDK in task transcript
# getModulesPaginated(SENTINEL_MODULES, 65): literal words, never derived from the relay constants.
PAGE65 = ("0xcc2f8452" "0000000000000000000000000000000000000000000000000000000000000001"
          "0000000000000000000000000000000000000000000000000000000000000041")
PAGES = {"page1": CALL, "page65": PAGE65}


def request(data=CALL, block="0x64", **extra):
    return {"jsonrpc": "2.0", "id": 7, "method": "eth_call",
            "params": [{"to": SAFE, "data": data, **extra}, block]}


def module_page(start, size):
    return "0xcc2f8452" + f"{start:064x}" + f"{size:064x}"


def allowed_module_reads():
    """Exact page 1 / page 65 at the explicit block, uppercase hex, latest and an above-uint64 canonical quantity."""
    allowed = {}
    for name, data in PAGES.items():
        allowed[f"{name}/block-0x64"] = request(data)
        allowed[f"{name}/uppercase-data"] = request("0x" + data[2:].upper())
        allowed[f"{name}/uppercase-block"] = request(data, "0xABC")
        allowed[f"{name}/latest"] = request(data, "latest")
        allowed[f"{name}/above-uint64"] = request(data, "0x10000000000000000")
    return allowed


def denied_module_reads():
    """Neighbouring pages, other starts, dirty ABI, extra fields, bad blocks and writes: each refused."""
    denied = {f"size-{size}": request(module_page(1, size)) for size in (0, 2, 64, 66, 2 ** 256 - 1)}
    for start in (0, 2, 1 | 1 << 160, 1 << 255):
        for size in (1, 65):
            denied[f"start-{start:x}/size-{size}"] = request(module_page(start, size))
    for name, data in PAGES.items():
        denied.update({
            f"{name}/short-selector": request(data[:9]),
            f"{name}/selector-only": request(data[:10]),
            f"{name}/short-word": request(data[:-2]),
            f"{name}/one-word": request(data[:74]),
            f"{name}/extra-byte": request(data + "00"),
            f"{name}/extra-word": request(data + "00" * 32),
            f"{name}/newline": request(data + "\n"),
            f"{name}/leading-space": request(" " + data),
            f"{name}/other-selector": request("0xcc2f8453" + data[10:]),
            f"{name}/dirty-padding": request(data[:74] + "1" + data[75:]),
            f"{name}/from": request(data, **{"from": SAFE}),
            f"{name}/value": request(data, value="0x0"),
            f"{name}/gas": request(data, gas="0x1"),
            f"{name}/pending": request(data, "pending"),
            f"{name}/earliest": request(data, "earliest"),
            f"{name}/leading-zero": request(data, "0x064"),
            f"{name}/above-uint256": request(data, "0x1" + "0" * 64),
            f"{name}/empty-block": request(data, ""),
            f"{name}/missing-block": {**request(data), "params": [{"to": SAFE, "data": data}]},
            f"{name}/numeric-block": {**request(data), "params": [{"to": SAFE, "data": data}, 100]},
            f"{name}/bad-to": {**request(data), "params": [{"to": SAFE[:-2], "data": data}, "0x64"]},
            f"{name}/missing-to": {**request(data), "params": [{"data": data}, "0x64"]},
        })
        for method in ("eth_sendTransaction", "eth_sendRawTransaction", "eth_estimateGas", "anvil_setCode"):
            denied[f"{name}/{method}"] = {**request(data), "method": method}
    return denied


def simulation():
    # Independently encoded native CALL; signatures are opaque relay input, not verified authority.
    recipient = "55" * 20
    signature = "44" * 65
    words = [int(recipient, 16), 1, 320, 0, 0, 0, 0, 0, 0, 352, 0, 65]
    data = "0x6a761202" + "".join(f"{n:064x}" for n in words) + signature + "00" * 31
    return {"jsonrpc": "2.0", "id": 8, "method": "eth_call", "params": [
        {"from": "0x" + "77" * 20, "to": SAFE, "value": "0x0", "data": data}, "0x64"]}


def denied_simulations():
    base = simulation()
    bad = []
    for tag in ["latest", "pending", "0x064", "0x10000000000000000"]:
        wire = json.loads(json.dumps(base)); wire["params"][1] = tag; bad.append(wire)
    for key, value in [("value", "0x1"), ("from", SAFE), ("from", "0x" + "00" * 20), ("gas", "0x1")]:
        wire = json.loads(json.dumps(base)); wire["params"][0][key] = value; bad.append(wire)
    for index, value in [(0, 0), (0, 1), (0, int(SAFE, 16)), (1, 0), (2, 352), (3, 1),
                         (4, 1), (5, 1), (6, 1), (7, 1), (8, 1), (9, 384), (10, 1), (11, 0), (11, 4097)]:
        wire = json.loads(json.dumps(base)); data = wire["params"][0]["data"]
        start = 10 + index * 64
        wire["params"][0]["data"] = data[:start] + f"{value:064x}" + data[start + 64:]; bad.append(wire)
    for data in [base["params"][0]["data"] + "00", base["params"][0]["data"][:-2],
                 base["params"][0]["data"][:-2] + "01", "0x6a761202", base["params"][0]["data"] + "\n"]:
        wire = json.loads(json.dumps(base)); wire["params"][0]["data"] = data; bad.append(wire)
    for method in ["eth_estimateGas", "eth_sendTransaction", "eth_sendRawTransaction", "anvil_setBalance"]:
        wire = json.loads(json.dumps(base)); wire["method"] = method; bad.append(wire)
    return bad


def owner_simulation(count=1, threshold=1):
    # Independent ABI: 68-byte self-call, padded to 96 bytes; EOA static signatures only.
    wire = simulation()
    inner = "0d582f13" + f"{int('55' * 20, 16):064x}{threshold:064x}"
    signature = (f"{1:064x}{2:064x}" + "1b") * count
    words = [int(SAFE, 16), 0, 320, 0, 0, 0, 0, 0, 0, 448, 68]
    wire["params"][0]["data"] = ("0x6a761202" + "".join(f"{n:064x}" for n in words)
        + inner + "00" * 28 + f"{65 * count:064x}" + signature + "00" * (-65 * count % 32))
    return wire


def denied_owner_simulations():
    data = owner_simulation()["params"][0]["data"]
    bad = []
    # Outer ABI words, inner selector/address/threshold, both padding regions, EOA r/s/v.
    for start, width, value in [
        *[(10 + i * 64, 64, f"{v:064x}") for i, v in
          [(0, int('55' * 20, 16)), (1, 1), (2, 352), (3, 1), (4, 1), (5, 1),
           (6, 1), (7, 1), (8, 1), (9, 352), (10, 67), (10, 69)]],
        (714, 8, "deadbeef"),
        *[(722, 64, f"{v:064x}") for v in [0, 1, int(SAFE, 16), 2 ** 160]],
        *[(786, 64, f"{v:064x}") for v in [0, 9]],
        (850, 56, "0" * 55 + "1"),
        *[(906, 64, f"{v:064x}") for v in [0, 64, 66, 520, 4097]],
        (970, 64, "0" * 64),
        (970, 64, f"{0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141:064x}"),
        (1034, 64, "0" * 64),
        (1034, 64, f"{0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1:064x}"),
        (1034, 64, "f" * 64),
        *[(1098, 2, v) for v in ["00", "01", "1f", "20", "ff"]],
        (1100, 62, "0" * 61 + "1"),
    ]:
        wire = owner_simulation()
        wire["params"][0]["data"] = data[:start] + value + data[start + width:]
        bad.append(wire)
    for malformed in [data + "00", data[:-2], data[:906], data + "\n"]:
        wire = owner_simulation(); wire["params"][0]["data"] = malformed; bad.append(wire)
    for method in ["eth_sendTransaction", "eth_sendRawTransaction", "eth_estimateGas"]:
        wire = owner_simulation(); wire["method"] = method; bad.append(wire)
    return bad


class Checks(unittest.TestCase):
    def test_owner_simulation_rejects_noncanonical_abi_and_non_eoa_signatures(self):
        for wire in denied_owner_simulations():
            with self.subTest(data=wire["params"][0]["data"]):
                self.assertIsNone(relay.validate_rpc(json.dumps(wire)))

    def test_canonical_owner_simulation(self):
        for count, threshold in [(1, 1), (7, 8)]:
            wire = owner_simulation(count, threshold)
            self.assertEqual(relay.validate_rpc(json.dumps(wire)), wire)

    def test_native_simulation_only_at_exact_block(self):
        wire = simulation()
        self.assertEqual(relay.validate_rpc(json.dumps(wire)), wire)
        for length in [65, 193, 4096]:
            candidate = simulation()
            data = candidate["params"][0]["data"][:714] + f"{length:064x}" + "44" * length + "00" * (-length % 32)
            candidate["params"][0]["data"] = data
            self.assertEqual(relay.validate_rpc(json.dumps(candidate)), candidate)
        for wire in denied_simulations():
            with self.subTest(wire=wire):
                self.assertIsNone(relay.validate_rpc(json.dumps(wire)))


    def test_client_version_read_without_parameters(self):
        wire = {"jsonrpc": "2.0", "id": 9, "method": "web3_clientVersion", "params": []}
        self.assertEqual(relay.validate_rpc(json.dumps(wire)), wire)
        for params in [["x"], [[]], [0], ["0x89"]]:
            self.assertIsNone(relay.validate_rpc(json.dumps({**wire, "params": params})))
        for method in ["web3_sha3", "net_version", "anvil_nodeInfo"]:
            self.assertIsNone(relay.validate_rpc(json.dumps({**wire, "method": method})))

    def test_exact_module_read(self):
        self.assertEqual(relay.validate_rpc(json.dumps(request())), request())
        # The page-65 call is the independent literal of selector + uint256(1) + uint256(65).
        self.assertEqual(PAGE65, module_page(1, 65))
        for name, wire in allowed_module_reads().items():
            with self.subTest(name=name):
                self.assertEqual(relay.validate_rpc(json.dumps(wire)), wire)

    def test_no_other_module_shape_or_write(self):
        for data in ["0xcc2f8452", CALL + "00", CALL + "\n", CALL[:-64] + f"{2:064x}",
                     "0xcc2f8452" + f"{2:064x}{1:064x}", "0xcc2f8452" + f"{0:064x}{1:064x}",
                     "0x6a761202" + "00" * 320, "0xdeadbeef"]:
            with self.subTest(data=data):
                self.assertIsNone(relay.validate_rpc(json.dumps(request(data))))
        self.assertIsNone(relay.validate_rpc(json.dumps(request(**{"from": SAFE}))))
        for method in ["eth_sendTransaction", "eth_sendRawTransaction", "anvil_setCode"]:
            wire = request()
            wire["method"] = method
            self.assertIsNone(relay.validate_rpc(json.dumps(wire)))
        for name, wire in denied_module_reads().items():
            with self.subTest(name=name):
                self.assertIsNone(relay.validate_rpc(json.dumps(wire)))

    def test_actual_handler_forwards_only_exact_shape(self):
        seen = []

        class Upstream(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_POST(self):
                q = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append(q)
                body = json.dumps({"jsonrpc": "2.0", "id": q["id"], "result": "0x"}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.addCleanup(upstream.server_close)
        t = threading.Thread(target=upstream.serve_forever, kwargs={"poll_interval": 0.02})
        t.start()
        self.addCleanup(t.join, 2)
        self.addCleanup(upstream.shutdown)
        # Bind before constructing handler to avoid free-port TOCTOU.
        server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        host = f"127.0.0.1:{server.server_port}"
        server.RequestHandlerClass = relay.make_handler({}, host, f"http://{host}",
                                                       f"http://127.0.0.1:{upstream.server_port}/rpc")
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)

        def post(wire, origin=f"http://{host}", path="/rpc", content_type="application/json", host_header=None):
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            headers = {"Content-Type": content_type, "Origin": origin}
            if host_header is not None:
                headers["Host"] = host_header
            try:
                connection.request("POST", path, body=json.dumps(wire), headers=headers)
                response = connection.getresponse()
                body = response.read()
                return response.status, body
            finally:
                connection.close()

        status, body = post(request())
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"jsonrpc": "2.0", "id": 7, "result": "0x"})
        self.assertEqual(seen, [request()])
        bad = [request(CALL + "00"), request(CALL[:-64] + f"{2:064x}"),
               {**request(), "method": "eth_sendTransaction"}, request(**{"from": SAFE})]
        for wire in bad:
            self.assertEqual(post(wire)[0], 403)
            self.assertEqual(seen, [request()], "denied request reached upstream")
        self.assertEqual(post(request(), "https://evil.example")[0], 403)
        self.assertEqual(seen, [request()])
        wire = simulation()
        self.assertEqual(post(wire)[0], 200)
        owner_wire = owner_simulation()
        self.assertEqual(post(owner_wire)[0], 200)
        expected = [request(), wire, owner_wire]
        self.assertEqual(seen, expected)
        for denied in denied_simulations() + denied_owner_simulations():
            self.assertEqual(post(denied)[0], 403)
            self.assertEqual(seen, expected, "denied simulation reached upstream")
        self.assertEqual(post(wire, "https://evil.example")[0], 403)
        self.assertEqual(seen, expected)
        # Exact module pages: each allowed shape reaches the counting upstream exactly once with unchanged params.
        for name, allowed in allowed_module_reads().items():
            with self.subTest(allowed=name):
                status, body = post(allowed)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body), {"jsonrpc": "2.0", "id": 7, "result": "0x"})
                expected = expected + [allowed]
                self.assertEqual(seen, expected)
                self.assertEqual(seen[-1]["params"], allowed["params"])
        for name, denied in denied_module_reads().items():
            with self.subTest(denied=name):
                self.assertEqual(post(denied)[0], 403)
                self.assertEqual(seen, expected, "denied module read reached upstream")
        # Wrong Origin, Host, path or content type is refused before validation, for both pages.
        for data in PAGES.values():
            for kwargs, status in [({"origin": "https://evil.example"}, 403), ({"host_header": "evil.example"}, 403),
                                   ({"path": "/rpc/137"}, 404), ({"path": "/rpc/"}, 404), ({"path": "/rpc?x"}, 404),
                                   ({"content_type": "text/plain"}, 415)]:
                with self.subTest(data=data, refused=kwargs):
                    self.assertEqual(post(request(data), **kwargs)[0], status)
                    self.assertEqual(seen, expected, "refused HTTP request reached upstream")


if __name__ == "__main__":
    unittest.main(verbosity=2)
    # No build/asset serving here; the real handler's POST boundary is the subject.
