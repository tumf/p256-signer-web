"""Serve a built directory through the real serve.py handler on loopback (test helper, no upstream).

Usage: serve-dist.py <dist> <public origin>. Prints `PORT <n>` and serves until stdin closes.
"""
import importlib.util
import socket
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread

spec = importlib.util.spec_from_file_location("server", Path(__file__).resolve().parents[2] / "serve.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)
server.DIST = Path(sys.argv[1]).resolve()
assets = server.load_assets()
with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
http = ThreadingHTTPServer(("127.0.0.1", port),
                           server.make_handler(assets, f"127.0.0.1:{port}", sys.argv[2], "http://127.0.0.1:1"))
Thread(target=http.serve_forever, daemon=True).start()
print(f"PORT {port}", flush=True)
sys.stdin.read()
http.shutdown()
http.server_close()
