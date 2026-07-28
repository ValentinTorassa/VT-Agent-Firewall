"""Mock exfiltration receiver on 127.0.0.1:8765.

In the firewall demo it must receive ZERO requests (that is the success
criterion). In --no-firewall contrast mode it shows what the attacker
would have collected. Loopback only, synthetic data only.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = "127.0.0.1", 8765


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        self.server.received.append({"path": self.path, "body": body})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"count": len(self.server.received)}).encode())

    def log_message(self, *args):  # silence per-request logging
        pass


def start_receiver() -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer((HOST, PORT), _Handler)
    server.received = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


if __name__ == "__main__":
    server, _ = start_receiver()
    print(f"mock receiver on http://{HOST}:{PORT}/collect (Ctrl-C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print(f"\nreceived {len(server.received)} payloads:")
        for r in server.received:
            print(" ", r)
