"""Integration test: run a real scan against an embedded, intentionally
vulnerable server (stdlib, in a background thread) and assert the form-based
XSS and SQLi are found end to end."""
import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

from vrt_scanner.core import Scope, HttpEngine, Crawler
from vrt_scanner.modules import ALL_MODULES

PAGE = ("<!doctype html><html><body><a href='/search'>s</a>"
        "<form method='POST' action='/login'>"
        "<input name='username'><input name='password' type='password'>"
        "</form></body></html>")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/":
            self._send(PAGE)
        elif p.path == "/search":
            q = parse_qs(p.query).get("q", [""])[0]
            self._send("You have an error in your SQL syntax; check the MySQL manual"
                       if "'" in q else f"results for {q}")
        else:
            self._send("not found", 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        user = parse_qs(self.rfile.read(n).decode()).get("username", [""])[0]
        self._send("ORA-00933: SQL command not properly ended"
                   if "'" in user else f"welcome {user}")


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


async def _scan(base):
    engine = HttpEngine(Scope(["127.0.0.1"]), rate=0)
    try:
        pages = await Crawler(engine, max_pages=10).crawl(base)
        findings = []
        for m in ALL_MODULES:
            if m.MANUAL:
                continue
            findings += await m.run(engine, pages)
    finally:
        await engine.aclose()
    return findings


def test_form_xss_and_sqli_found(server):
    findings = asyncio.run(_scan(server))
    ids = {f.vrt_id for f in findings}
    assert "cross_site_scripting_xss.reflected.non_self" in ids
    assert "server_side_injection.sql_injection" in ids
