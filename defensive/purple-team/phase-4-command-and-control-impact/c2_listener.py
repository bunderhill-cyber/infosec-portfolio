#!/usr/bin/env python3
"""
Purple Team Phase 4 - Simple Educational C2 Listener (HTTP)

Run this on Slingshot (or any lab Linux host) before starting
Invoke-C2BeaconDemo.ps1 on the Windows VM.

Usage:
    python3 c2_listener.py                  # binds 0.0.0.0:8080
    python3 c2_listener.py --port 8080
    python3 c2_listener.py --cmd whoami     # return this command on next beacon

Only educational. Accepts beacons, logs them, and can return one
allow-listed command (the beacon enforces its own allow-list).

AUTHORIZED LAB USE ONLY.
"""

import argparse
import json
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# Configuration (overridden by CLI)
# ---------------------------------------------------------------------------
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080
PENDING_CMD = None          # set via --cmd or interactively later
BEACON_LOG  = []

class C2Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # quieter than default
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), format % args))

    def _send(self, code=200, body="OK", content_type="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.wfile.write(body)

    def do_GET(self):
        global PENDING_CMD
        parsed = urlparse(self.path)
        if parsed.path.rstrip("/") != "/beacon":
            self._send(404, "Not Found")
            return

        qs = parse_qs(parsed.query)
        beacon_id = qs.get("id", ["?"])[0]
        seq       = qs.get("seq", ["?"])[0]
        host      = qs.get("host", ["?"])[0]
        user      = qs.get("user", ["?"])[0]

        entry = {
            "time": datetime.utcnow().isoformat() + "Z",
            "method": "GET",
            "beacon_id": beacon_id,
            "sequence": seq,
            "hostname": host,
            "username": user,
        }
        BEACON_LOG.append(entry)
        print(f"\n[+] GET Beacon  id={beacon_id}  seq={seq}  host={host}  user={user}")

        # Return pending command if set, otherwise just acknowledge
        if PENDING_CMD:
            body = f"CMD:{PENDING_CMD}"
            print(f"    → returning command: {PENDING_CMD}")
            PENDING_CMD = None          # one-shot
        else:
            body = "OK"
        self._send(200, body)

    def do_POST(self):
        global PENDING_CMD
        parsed = urlparse(self.path)
        if parsed.path.rstrip("/") != "/beacon":
            self._send(404, "Not Found")
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

        try:
            data = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            data = {"raw": raw}

        beacon_id = data.get("beacon_id", "?")
        seq       = data.get("sequence", "?")
        host      = data.get("hostname", "?")
        user      = data.get("username", "?")
        last_res  = data.get("last_result", "")

        entry = {
            "time": datetime.utcnow().isoformat() + "Z",
            "method": "POST",
            "beacon_id": beacon_id,
            "sequence": seq,
            "hostname": host,
            "username": user,
            "last_result_len": len(last_res),
        }
        BEACON_LOG.append(entry)

        print(f"\n[+] POST Beacon  id={beacon_id}  seq={seq}  host={host}  user={user}")
        if last_res:
            preview = last_res[:200].replace("\n", " ")
            print(f"    last_result preview: {preview}...")

        if PENDING_CMD:
            body = f"CMD:{PENDING_CMD}"
            print(f"    → returning command: {PENDING_CMD}")
            PENDING_CMD = None
        else:
            body = "OK"
        self._send(200, body)

def main():
    global LISTEN_PORT, PENDING_CMD

    parser = argparse.ArgumentParser(description="Purple Team Phase 4 - Educational C2 Listener")
    parser.add_argument("--host", default=LISTEN_HOST, help="Bind address (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=LISTEN_PORT, help="Listen port (default 8080)")
    parser.add_argument("--cmd",  default=None, help="One-shot command to return on next beacon (e.g. whoami)")
    args = parser.parse_args()

    LISTEN_PORT = args.port
    PENDING_CMD = args.cmd

    print("=" * 60)
    print("  PURPLE TEAM PHASE 4 - Educational C2 Listener")
    print("  AUTHORIZED LAB USE ONLY")
    print("=" * 60)
    print(f"[*] Listening on http://{args.host}:{LISTEN_PORT}/beacon")
    if PENDING_CMD:
        print(f"[*] Will return command on next beacon: {PENDING_CMD}")
    print("[*] Press Ctrl+C to stop")
    print()

    server = HTTPServer((args.host, LISTEN_PORT), C2Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Listener stopped.")
        print(f"[*] Total beacons received: {len(BEACON_LOG)}")
        if BEACON_LOG:
            print("[*] Last few entries:")
            for e in BEACON_LOG[-5:]:
                print(f"    {e}")

if __name__ == "__main__":
    main()
