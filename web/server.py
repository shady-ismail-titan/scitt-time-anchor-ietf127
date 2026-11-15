#!/usr/bin/env python3
"""Static HTTP server with strict offline Content-Security-Policy for the WASM lab."""
from __future__ import annotations

import argparse
import http.server
from pathlib import Path
import socketserver

WEB_ROOT = Path(__file__).resolve().parent


def make_handler(secret_prefix: str | None):
    prefix = secret_prefix.rstrip("/") if secret_prefix else None

    class OfflineLabHandler(http.server.SimpleHTTPRequestHandler):
        extensions_map = {
            **http.server.SimpleHTTPRequestHandler.extensions_map,
            ".wasm": "application/wasm",
        }

        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

        def end_headers(self) -> None:
            self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-ancestors 'none'",
            )
            super().end_headers()

        def _rewrite_prefix(self) -> str:
            raw_path, sep, query = self.path.partition("?")
            if raw_path.endswith("/favicon.ico") or raw_path == "/favicon.ico":
                return "__FAVICON_204__"
            if prefix:
                if raw_path == prefix or raw_path == prefix + "/":
                    rewritten = "/index.html"
                elif raw_path.startswith(prefix + "/"):
                    rewritten = raw_path[len(prefix):] or "/index.html"
                else:
                    return "__NOT_FOUND_404__"
                self.path = f"{rewritten}?{query}" if sep else rewritten
            return "OK"

        def do_HEAD(self) -> None:
            status = self._rewrite_prefix()
            if status == "__FAVICON_204__":
                self.send_response(204)
                self.end_headers()
                return
            if status == "__NOT_FOUND_404__":
                self.send_error(404, "Not Found")
                return
            return super().do_HEAD()

        def do_GET(self) -> None:
            status = self._rewrite_prefix()
            if status == "__FAVICON_204__":
                self.send_response(204)
                self.end_headers()
                return
            if status == "__NOT_FOUND_404__":
                self.send_error(404, "Not Found")
                return
            return super().do_GET()

        def log_message(self, format: str, *args) -> None:
            return

    return OfflineLabHandler


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the offline SCITT Time-Anchor WASM Lab.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--prefix", default=None, help="Optional URL path prefix")
    args = parser.parse_args()
    handler = make_handler(args.prefix)
    with ReusableTCPServer((args.host, args.port), handler) as httpd:
        print(f"Serving {WEB_ROOT} on http://{args.host}:{args.port}{args.prefix or '/'}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
