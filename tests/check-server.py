"""Real local HTTP checks of serve.py against a fake read-only upstream on loopback.

Positive block-bound reads are forwarded; every forbidden method/body/origin/Host/path/redirect/size case
is rejected before (or instead of) forwarding. External network is never used: the only upstream is the
loopback fake, and the gate fails if serve.py contacts anything else. Prints one JSON summary line.
"""
import hashlib
import http.client
import json
import re
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
APP = HERE.parent
FACTORY = "0x69Aa2f9fe1572F1B640E1bbc512f5c3a734fc77c"
ACCOUNT = "0x1111111111111111111111111111111111111111"
ENTRYPOINT = "0x0000000071727de22e5e9d8baf0edac6f37da032"
# Hybrid context reader reads: getNonce(address,uint192) = sender word || key word (key 0 only).
NONCE_CALL = "0x35567e1a" + "00" * 12 + ACCOUNT[2:] + "00" * 32
KEY_ID = "ab" * 32
PROJECT_ID = "0123456789abcdef0123456789abcdef"
results = {}
failures = []


def check(name, condition, detail=""):
    results[name] = "pass" if condition else f"FAIL {detail}"
    if not condition:
        failures.append(f"{name}: {detail}")


class Upstream(BaseHTTPRequestHandler):
    seen = []
    mode = {"redirect": False, "huge": False, "wrong_id": False}

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        Upstream.seen.append(json.loads(body))
        if Upstream.mode["redirect"]:
            self.send_response(307)
            self.send_header("Location", "http://127.0.0.1:9/elsewhere")
            self.end_headers()
            return
        request = json.loads(body)
        payload = {"jsonrpc": "2.0", "id": request["id"] + (1 if Upstream.mode["wrong_id"] else 0),
                   "result": "0x89" if request["method"] == "eth_chainId" else "0x1"}
        data = json.dumps(payload).encode()
        if Upstream.mode["huge"]:
            data = json.dumps({**payload, "result": "0x" + "00" * 1_100_000}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            # The relay stops reading an oversized upstream response at its ceiling; that hang-up is expected.
            pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def request(port, method, path, body=None, host=None, origin="default", content_type="application/json",
            length=None):
    host = host or f"127.0.0.1:{port}"
    headers = {"Host": host}
    if origin == "default":
        origin = f"http://127.0.0.1:{port}"
    if origin is not None:
        headers["Origin"] = origin
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(length if length is not None else len(data))
    else:
        data = None
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    for key, value in headers.items():
        connection.putheader(key, value)
    connection.endheaders()
    if data is not None:
        connection.send(data)
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    return response.status, dict(response.getheaders()), payload


def start(port, upstream_port, project=None, app=APP):
    env = {k: v for k, v in os.environ.items() if k not in ("WALLETCONNECT_PROJECT_ID", "POLYGON_RPC_URL")}
    env.update(REGISTRATION_PORT=str(port), POLYGON_RPC_URL=f"http://127.0.0.1:{upstream_port}/rpc")
    if project is not None:
        env["WALLETCONNECT_PROJECT_ID"] = project
    process = subprocess.Popen([sys.executable, str(app / "serve.py")], env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    for _ in range(50):
        if process.poll() is not None:
            return process
        try:
            status, _, _ = request(port, "GET", "/config.json")
            if status == 200:
                return process
        except OSError:
            pass
        time.sleep(0.1)
    return process

# Recompute, independently of build.mjs, every node_modules package directory esbuild pulls into app.js's chunks
# (AppKit stubbed as in the build), resolving the innermost node_modules/<pkg|@scope/pkg> of each metafile input.
METAFILE_PROBE = r"""
import * as esbuild from 'esbuild';
const stub = { name: 'stub', setup(b) {
  b.onResolve({ filter: /^@reown\/appkit/ }, (a) => ({ path: a.path, namespace: 'stub' }));
  b.onLoad({ filter: /.*/, namespace: 'stub' }, () => ({ contents: '', loader: 'js' })); } };
const r = await esbuild.build({ absWorkingDir: process.cwd(), entryPoints: ['app.js'], bundle: true, splitting: true,
  format: 'esm', outdir: 'probe-out', write: false, platform: 'browser', target: ['es2022'], metafile: true,
  logLevel: 'silent', define: { 'process.env.NODE_ENV': '"production"', global: 'globalThis' }, plugins: [stub] });
const dirs = new Set();
for (const input of Object.keys(r.metafile.inputs)) {
  const at = input.lastIndexOf('node_modules/');
  if (at < 0) continue;
  const rest = input.slice(at + 13).split('/');
  dirs.add(input.slice(0, at + 13) + (rest[0].startsWith('@') ? rest[0] + '/' + rest[1] : rest[0]));
}
console.log(JSON.stringify([...dirs].sort()));
"""


def expected_packages():
    """{name@version: [package dirs]} for every package esbuild bundles, read from each package.json."""
    out = subprocess.run(["node", "--input-type=module", "-e", METAFILE_PROBE], cwd=APP, capture_output=True,
                         text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(out.stderr[-300:])
    expected = {}
    for directory in json.loads(out.stdout):
        meta = json.loads((APP / directory / "package.json").read_text())
        expected.setdefault(f"{meta['name']}@{meta['version']}", []).append(directory)
    return expected


def notice_sections(text):
    """Parse NOTICES.txt package sections into {name@version: {"fields": {...}, "paths": [...], "texts": [...]}}."""
    sections, current = {}, None
    for line in text.split("\n"):
        if line.startswith("==== BEGIN PACKAGE ") and line.endswith(" ===="):
            current = {"fields": {}, "paths": [], "texts": [], "copyrights": [], "id": line[19:-5]}
        elif current is not None and line == f"==== END PACKAGE {current['id']} ====":
            sections[current["id"]] = current
            current = None
        elif current is not None and line.startswith("---- license text: "):
            current["texts"].append([line, []])
        elif current is not None and current["texts"]:
            current["texts"][-1][1].append(line)
        elif current is not None and ": " in line:
            key, value = line.split(": ", 1)
            if key == "path":
                current["paths"].append(value)
            elif key == "copyright":
                current["copyrights"].append(value)
                current["fields"].setdefault(key, value)
            else:
                current["fields"].setdefault(key, value)
    return sections


def check_notices(notices):
    """Every bundled package (including nested node_modules copies) is named with its full license text."""
    text = notices.decode("utf-8")
    sections = notice_sections(text)
    try:
        expected = expected_packages()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        check("notices-expected-set", False, f"metafile probe failed: {error}")
        return
    check("notices-expected-set", len(expected) >= 20, f"{len(expected)} packages")
    missing = sorted(set(expected) - set(sections))
    check("notices-all-bundled-packages", not missing, f"missing {missing}")
    wrong_paths = sorted(pid for pid, dirs in expected.items()
                         if pid in sections and not set(dirs) <= set(sections[pid]["paths"]))
    check("notices-nested-paths", not wrong_paths, f"paths differ for {wrong_paths}")
    nested = APP / "node_modules/@walletconnect/utils/node_modules"
    for rel in ("ox", "@noble/hashes", "@noble/curves", "abitype", "ox/node_modules/@noble/curves"):
        meta = json.loads((nested / rel / "package.json").read_text())
        pid = f"{meta['name']}@{meta['version']}"
        check(f"notices-nested {rel}", pid in sections and f"  {pid} " in text
              and f"node_modules/@walletconnect/utils/node_modules/{rel}" in sections[pid]["paths"], pid)
    for pid, section in sorted(sections.items()):
        bodies = ["\n".join(body).strip() for _, body in section["texts"]]
        has_text = bool(bodies) and all(bodies)
        fallback = any("no license file shipped" in header for header, _ in section["texts"])
        problems = []
        if not has_text:
            problems.append("empty license text")
        if not section["fields"].get("license") or not section["fields"].get("copyright"):
            problems.append("missing license id or copyright line")
        try:
            on_disk = sorted(f.name for f in (APP / section["paths"][0]).iterdir()
                             if f.is_file() and f.name.lower().startswith(("licence", "license", "copying", "notice")))
        except (OSError, IndexError) as error:
            on_disk = None
            problems.append(f"package directory unreadable: {error}")
        if on_disk is not None and fallback and on_disk:
            problems.append(f"claims no license file but ships {on_disk}")
        if on_disk is not None and not fallback:
            names = [h[len("---- license text: "):-len(" ----")] for h, _ in section["texts"]]
            if names != on_disk:
                problems.append(f"license files differ from {on_disk}")
            else:
                # Each served text equals the shipped file (newline-normalised, trailing space trimmed).
                for name, body in zip(names, bodies):
                    shipped = (APP / section["paths"][0] / name).read_text(errors="replace").replace("\r\n", "\n").strip()
                    if body != shipped:
                        problems.append(f"{name} text differs from the shipped file")
                shipped_copyright = [line.strip() for body in bodies for line in body.split("\n")
                                     if re.match(r"(?i)^(copyright\b|\(c\)|©)", line.strip())]
                if shipped_copyright and not all(f"copyright: {line}" in "\n".join(
                        f"copyright: {v}" for v in section["copyrights"]) for line in shipped_copyright):
                    problems.append("shipped copyright lines not listed")
        # MIT texts carry the grant; dijkstrajs ships only "Licensed under the MIT license" plus the MIT URL.
        if "MIT" in section["fields"].get("license", "") and not any(
                "Permission is hereby granted" in body or "Licensed under the MIT license" in body for body in bodies):
            problems.append("MIT text lacks permission grant")
        check(f"notices-text {pid}", not problems, "; ".join(problems))


def rpc(method, params):
    return {"jsonrpc": "2.0", "id": 7, "method": method, "params": params}


def main():
    upstream_port = free_port()
    upstream = ThreadingHTTPServer(("127.0.0.1", upstream_port), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    port = free_port()
    server = start(port, upstream_port)
    try:
        check("server-ready", server.poll() is None, "serve.py did not start")
        # Static allowlist, headers and licenses.
        status, headers, body = request(port, "GET", "/")
        check("index", status == 200 and b"01 / PUBLIC PLAN" in body)
        for name in ("Content-Security-Policy", "Cache-Control", "X-Content-Type-Options", "Referrer-Policy"):
            check(f"header-{name}", name in headers, str(headers))
        csp = headers.get("Content-Security-Policy", "")
        check("csp", "script-src 'self'" in csp and "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
              and "connect-src 'self' wss://relay.walletconnect.com https://relay.walletconnect.com" in csp
              and "frame-ancestors 'none'" in csp and "*" not in csp, csp)
        check("no-referrer", headers.get("Referrer-Policy") == "no-referrer")
        check("no-store", headers.get("Cache-Control") == "no-store")
        check("no-cors", "Access-Control-Allow-Origin" not in headers)
        status, _, served = request(port, "GET", "/licenses/walletconnect-LICENSE.md")
        vendor = (APP / "vendor/walletconnect-LICENSE.md").read_bytes()
        original = (APP / "node_modules/@walletconnect/ethereum-provider/LICENSE.md").read_bytes()
        check("license-bytes", status == 200 and served == vendor == original
              and hashlib.sha256(served).hexdigest() == next(entry["sha256"] for entry in
                  json.loads((APP / "licenses.json").read_text())["packages"]
                  if entry["package"] == "@walletconnect/ethereum-provider"))
        check("license-text", b"WALLETCONNECT COMMUNITY LICENSE AGREEMENT" in served and b"20 August 2025" in served)
        status, _, notices = request(port, "GET", "/licenses/NOTICES.txt")
        check("notices", status == 200 and "Portions © 2025 Reown, Inc. All Rights Reserved".encode() in notices)
        check_notices(notices)
        manifest = json.loads((APP / "dist/asset-manifest.json").read_text())
        lazy = [name for name in manifest["files"] if name.startswith("chunks/walletconnect-")]
        status, _, chunk = request(port, "GET", "/" + lazy[0]) if lazy else (0, {}, b"")
        check("lazy-chunk-notice", status == 200
              and chunk.startswith("/*! Portions © 2025 Reown, Inc. All Rights Reserved".encode()))
        status, _, index = request(port, "GET", "/index.html")
        check("footer-notice", "Portions © 2025 Reown, Inc. All Rights Reserved".encode() in index
              and b'href="licenses/NOTICES.txt"' in index)
        for path in ("/model.js", "/serve.py", "/../serve.py", "/%2e%2e/serve.py", "/vendor/proxy.json",
                     "/node_modules/qrcode/package.json", "/?registration=abc", "/dist/app.js", "/tests/check-server.py",
                     "/asset-manifest.json", "//etc/passwd"):
            status, _, _ = request(port, "GET", path)
            check(f"static-deny {path}", status == 404, str(status))
        status, _, config = request(port, "GET", "/config.json")
        check("config-null", json.loads(config) == {"walletConnectProjectId": None,
                                                     "allowedDeploymentOrigin": "https://p256-signer.mini.tumf.dev"})
        check("bad-host-get", request(port, "GET", "/", host="evil.example")[0] == 403)
        # Positive read-only forwarding.
        before = len(Upstream.seen)
        positives = [
            rpc("eth_chainId", []), rpc("eth_blockNumber", []), rpc("eth_maxPriorityFeePerGas", []),
            rpc("eth_getBlockByNumber", ["latest", False]), rpc("eth_getBlockByNumber", ["0x5b21f24", True]),
            rpc("eth_getCode", [FACTORY, "0x5b21f24"]),
            rpc("eth_getStorageAt", [FACTORY, "0x" + "00" * 32, "0x5b21f24"]),
            rpc("eth_call", [{"to": FACTORY, "data": "0x481286e6" + "00" * 64}, "0x5b21f24"]),
            rpc("eth_call", [{"to": ACCOUNT, "data": "0x8da5cb5b"}, "0x10"]),
            rpc("eth_call", [{"to": ACCOUNT, "data": "0x1c03010a"}, "0x10"]),
            rpc("eth_call", [{"to": ACCOUNT, "data": "0xd37aec92" + "00" * 31 + "20" + "00" * 31 + "40"
                              + KEY_ID.encode().hex()}, "0x10"]),
            rpc("eth_call", [{"to": ACCOUNT, "data": "0xb0d691fe"}, "0x10"]),
            rpc("eth_call", [{"to": ACCOUNT, "data": "0x2ffeaad6"}, "0x10"]),
            rpc("eth_call", [{"to": ENTRYPOINT, "data": NONCE_CALL}, "0x10"]),
            rpc("eth_estimateGas", [{"from": ACCOUNT, "to": FACTORY, "data": "0x4af63f02" + "00" * 64,
                                     "value": "0x0"}, "0x5b21f24"]),
            rpc("eth_getTransactionCount", [ACCOUNT, "pending"]),
            rpc("eth_getTransactionByHash", ["0x" + "ab" * 32]), rpc("eth_getTransactionReceipt", ["0x" + "ab" * 32]),
        ]
        for item in positives:
            status, _, body = request(port, "POST", "/rpc", item)
            check(f"forward {item['method']}", status == 200 and json.loads(body)["id"] == 7, f"{status} {body[:80]}")
        check("forwarded-count", len(Upstream.seen) - before == len(positives))
        # Rejected before forwarding.
        before = len(Upstream.seen)
        forbidden = {
            "sendRaw": rpc("eth_sendRawTransaction", ["0x00"]),
            "sendTransaction": rpc("eth_sendTransaction", [{"from": ACCOUNT, "to": FACTORY}]),
            "sign": rpc("eth_sign", [ACCOUNT, "0x00"]), "personal_sign": rpc("personal_sign", ["0x00", ACCOUNT]),
            "typed": rpc("eth_signTypedData_v4", [ACCOUNT, "{}"]),
            "unlock": rpc("personal_unlockAccount", [ACCOUNT, "pw"]), "accounts": rpc("eth_accounts", []),
            "debug": rpc("debug_traceTransaction", ["0x" + "ab" * 32]), "anvil": rpc("anvil_setBalance", [ACCOUNT, "0x1"]),
            "wallet": rpc("wallet_switchEthereumChain", [{"chainId": "0x89"}]),
            "estimate-other-target": rpc("eth_estimateGas", [{"from": ACCOUNT, "to": ACCOUNT, "data": "0x4af63f02",
                                                             "value": "0x0"}, "latest"]),
            "estimate-no-block": rpc("eth_estimateGas", [{"from": ACCOUNT, "to": FACTORY, "data": "0x4af63f02",
                                                         "value": "0x0"}]),
            "estimate-value": rpc("eth_estimateGas", [{"from": ACCOUNT, "to": FACTORY, "data": "0x4af63f02",
                                                      "value": "0x1"}, "latest"]),
            "call-arbitrary-selector": rpc("eth_call", [{"to": FACTORY, "data": "0xa9059cbb" + "00" * 64}, "latest"]),
            "call-predict-elsewhere": rpc("eth_call", [{"to": ACCOUNT, "data": "0x481286e6" + "00" * 64}, "latest"]),
            "call-extra-field": rpc("eth_call", [{"to": FACTORY, "data": "0x481286e6", "from": ACCOUNT}, "latest"]),
            "nonce-wrong-target": rpc("eth_call", [{"to": ACCOUNT, "data": NONCE_CALL}, "0x10"]),
            "nonce-nonzero-key": rpc("eth_call", [{"to": ENTRYPOINT, "data": NONCE_CALL[:-2] + "01"}, "0x10"]),
            "nonce-address-padding": rpc("eth_call", [{"to": ENTRYPOINT,
                                                      "data": NONCE_CALL[:10] + "01" + NONCE_CALL[12:]}, "0x10"]),
            "nonce-zero-sender": rpc("eth_call", [{"to": ENTRYPOINT,
                                                  "data": "0x35567e1a" + "00" * 64}, "0x10"]),
            "nonce-short": rpc("eth_call", [{"to": ENTRYPOINT, "data": NONCE_CALL[:-2]}, "0x10"]),
            "nonce-long": rpc("eth_call", [{"to": ENTRYPOINT, "data": NONCE_CALL + "00"}, "0x10"]),
            "nonce-newline": rpc("eth_call", [{"to": ENTRYPOINT, "data": NONCE_CALL + "\n"}, "0x10"]),
            "nonce-target-newline": rpc("eth_call", [{"to": ENTRYPOINT + "\n", "data": NONCE_CALL}, "0x10"]),
            "entrypoint-argument": rpc("eth_call", [{"to": ACCOUNT, "data": "0xb0d691fe" + "00" * 32}, "0x10"]),
            "entrypoint-trailing-byte": rpc("eth_call", [{"to": ACCOUNT, "data": "0xb0d691fe00"}, "0x10"]),
            "hashes-argument": rpc("eth_call", [{"to": ACCOUNT, "data": "0x2ffeaad6" + "00" * 32}, "0x10"]),
            "hashes-target-newline": rpc("eth_call", [{"to": ACCOUNT + "\n", "data": "0x2ffeaad6"}, "0x10"]),
            "pending-tag": rpc("eth_getCode", [FACTORY, "pending"]),
            "url-param": rpc("eth_getCode", ["https://evil.example", "latest"]),
            "extra-member": {**rpc("eth_chainId", []), "url": "https://evil.example"},
            "no-jsonrpc": {"id": 1, "method": "eth_chainId", "params": []},
            "bool-id": {**rpc("eth_chainId", []), "id": True},
        }
        for name, item in forbidden.items():
            status, _, _ = request(port, "POST", "/rpc", item)
            check(f"reject {name}", status == 403, str(status))
        status, _, _ = request(port, "POST", "/rpc", [rpc("eth_chainId", [])])
        check("reject batch", status == 403, str(status))
        status, _, _ = request(port, "POST", "/rpc", b"{" + b" " * 40000 + b"}")
        check("reject oversize", status == 413, str(status))
        status, _, _ = request(port, "POST", "/rpc", b"not json")
        check("reject malformed", status == 403, str(status))
        status, _, _ = request(port, "POST", "/rpc", rpc("eth_chainId", []), content_type="text/plain")
        check("reject content-type", status == 415, str(status))
        status, _, _ = request(port, "POST", "/rpc", rpc("eth_chainId", []), origin="https://evil.example")
        check("reject cross-origin", status == 403, str(status))
        status, _, _ = request(port, "POST", "/rpc", rpc("eth_chainId", []), origin=None)
        check("reject missing-origin", status == 403, str(status))
        status, _, _ = request(port, "POST", "/rpc", rpc("eth_chainId", []), host="evil.example")
        check("reject host", status == 403, str(status))
        status, _, _ = request(port, "POST", "/rpc/../x", rpc("eth_chainId", []))
        check("reject path", status == 404, str(status))
        status, _, _ = request(port, "POST", "/rpc?url=https://evil.example", rpc("eth_chainId", []))
        check("reject query", status == 404, str(status))
        status, _, _ = request(port, "PUT", "/rpc", rpc("eth_chainId", []))
        check("reject put", status in (403, 405), str(status))
        check("nothing-forwarded", len(Upstream.seen) == before, f"{len(Upstream.seen) - before} forwarded")
        # Upstream behaviour: redirect not followed, oversized and mismatched responses rejected.
        Upstream.mode["redirect"] = True
        before = len(Upstream.seen)
        status, _, _ = request(port, "POST", "/rpc", rpc("eth_chainId", []))
        check("redirect-not-followed", status == 502 and len(Upstream.seen) == before + 1, str(status))
        Upstream.mode.update(redirect=False, huge=True)
        check("oversize-response", request(port, "POST", "/rpc", rpc("eth_chainId", []))[0] == 502)
        Upstream.mode.update(huge=False, wrong_id=True)
        check("mismatched-id", request(port, "POST", "/rpc", rpc("eth_chainId", []))[0] == 502)
        Upstream.mode["wrong_id"] = False
        # Logging: nothing written by the server for requests (payloads never reach diagnostics).
    finally:
        server.terminate()
        out, err = server.communicate(timeout=10)
    check("no-request-logging", "registration=" not in out + err and "eth_" not in out + err
          and "GET" not in out + err, (out + err)[-200:])
    # Fixed public config with a valid/invalid ID.
    for project, expected in ((PROJECT_ID, PROJECT_ID), ("not-an-id", None)):
        port = free_port()
        server = start(port, upstream_port, project=project)
        try:
            status, _, body = request(port, "GET", "/config.json")
            check(f"config {project}", status == 200 and json.loads(body)["walletConnectProjectId"] == expected)
        finally:
            server.terminate()
            server.communicate(timeout=10)
    # Startup refuses a changed proxy artifact, a changed asset or a changed served license.
    for name, mutate in (("proxy", lambda d: (d / "vendor/proxy.json").write_bytes(b"{}")),
                         ("asset", lambda d: (d / "dist/app.js").write_bytes(b"//")),
                         ("license", lambda d: (d / "vendor/walletconnect-LICENSE.md").write_bytes(b"x"))):
        with tempfile.TemporaryDirectory() as temp:
            copy = Path(temp) / "registration"
            copy.mkdir()
            shutil.copy(APP / "serve.py", copy)
            shutil.copytree(APP / "vendor", copy / "vendor")
            shutil.copytree(APP / "dist", copy / "dist")
            mutate(copy)
            port = free_port()
            process = start(port, upstream_port, app=copy)
            try:
                code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                code = None
            _, err = process.communicate(timeout=10)
            check(f"refuse-start {name}", code not in (None, 0) and "refusing to start" in err, err[-200:])
    upstream.shutdown()
    summary = {"suite": "check-server", "checks": len(results), "failed": len(failures), "results": results}
    print(json.dumps(summary, ensure_ascii=False))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
