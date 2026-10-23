"""Vulnerability check modules. Each module maps to one VRT leaf id.

To add coverage: subclass Module, set VRT_ID / NAME / DEFAULT_PRIORITY,
implement run(), and add it to ALL_MODULES at the bottom. The orchestrator
pulls the real name/priority from vrt.json using VRT_ID when available and
falls back to the module's own defaults otherwise.

These modules cover the deterministic, automatable slice of the VRT. Context-
heavy classes (IDOR, access control, business logic) are left as explicit
TODO stubs — they need app-specific knowledge and human verification.
"""
from __future__ import annotations

import re

import httpx

from .core import (
    Finding, Page, HttpEngine, OutOfScope, query_params, set_query_param,
)


class Module:
    VRT_ID: str = ""
    NAME: str = ""
    DEFAULT_PRIORITY: int = 3

    async def run(self, engine: HttpEngine, pages: list[Page]) -> list[Finding]:
        raise NotImplementedError

    def finding(self, url, evidence, param=None, detail="") -> Finding:
        return Finding(vrt_id=self.VRT_ID, title=self.NAME, url=url,
                       evidence=evidence, priority=self.DEFAULT_PRIORITY,
                       param=param, detail=detail)


async def _safe_get(engine, url, **kw):
    try:
        return await engine.get(url, **kw)
    except (OutOfScope, httpx.HTTPError):
        return None


# --------------------------------------------------------------------------- #
# Passive header / config checks (inspect responses the crawler already got)
# --------------------------------------------------------------------------- #
class SecurityHeaders(Module):
    VRT_ID = "server_security_misconfiguration.missing_security_headers"
    NAME = "Missing security header"
    DEFAULT_PRIORITY = 5
    CHECKS = {
        "content-security-policy": "No Content-Security-Policy",
        "strict-transport-security": "No HSTS (Strict-Transport-Security)",
        "x-content-type-options": "No X-Content-Type-Options: nosniff",
        "referrer-policy": "No Referrer-Policy",
    }

    async def run(self, engine, pages):
        out = []
        if not pages:
            return out
        h = {k.lower(): v for k, v in pages[0].headers.items()}
        for header, title in self.CHECKS.items():
            if header not in h:
                out.append(Finding(self.VRT_ID, title, pages[0].url,
                                   evidence=f"response header '{header}' absent",
                                   priority=self.DEFAULT_PRIORITY))
        return out


class Clickjacking(Module):
    VRT_ID = "server_security_misconfiguration.clickjacking"
    NAME = "Clickjacking: no frame protection"
    DEFAULT_PRIORITY = 4

    async def run(self, engine, pages):
        if not pages:
            return []
        h = {k.lower(): v for k, v in pages[0].headers.items()}
        csp = h.get("content-security-policy", "")
        if "x-frame-options" not in h and "frame-ancestors" not in csp:
            return [self.finding(pages[0].url,
                    "neither X-Frame-Options nor CSP frame-ancestors present")]
        return []


class CookieSecurity(Module):
    VRT_ID = "server_security_misconfiguration.missing_secure_or_httponly_cookie_flag"
    NAME = "Cookie missing Secure/HttpOnly flag"
    DEFAULT_PRIORITY = 4

    async def run(self, engine, pages):
        out = []
        if not pages:
            return out
        r = await _safe_get(engine, pages[0].url)
        if r is None:
            return out
        for raw in r.headers.get_list("set-cookie"):
            name = raw.split("=", 1)[0].strip()
            low = raw.lower()
            missing = [f for f in ("secure", "httponly") if f not in low]
            if missing:
                out.append(self.finding(
                    pages[0].url,
                    f"cookie '{name}' missing flag(s): {', '.join(missing)}"))
        return out


# --------------------------------------------------------------------------- #
# Active injection checks (inject into query params found while crawling)
# --------------------------------------------------------------------------- #
class ReflectedXSS(Module):
    VRT_ID = "cross_site_scripting_xss.reflected"
    NAME = "Reflected XSS (unescaped reflection)"
    DEFAULT_PRIORITY = 3
    MARKER = "vrtx9z7q"
    PAYLOAD = f"<{MARKER}>"

    async def run(self, engine, pages):
        out = []
        for page in pages:
            for param in query_params(page.url):
                test = set_query_param(page.url, param, self.PAYLOAD)
                r = await _safe_get(engine, test)
                if r is not None and self.PAYLOAD in r.text:
                    out.append(self.finding(
                        test, f"payload '{self.PAYLOAD}' reflected unescaped",
                        param=param))
        return out


class SQLInjection(Module):
    VRT_ID = "server_side_injection.sql_injection"
    NAME = "SQL injection (error-based)"
    DEFAULT_PRIORITY = 1
    ERRORS = [
        r"SQL syntax.*MySQL", r"Warning.*\Wmysqli?_",
        r"PostgreSQL.*ERROR", r"org\.postgresql\.util\.PSQLException",
        r"ORA-\d{5}", r"Microsoft OLE DB Provider for SQL Server",
        r"SQLite/JDBCDriver", r"SQLITE_ERROR", r"unclosed quotation mark",
        r"quoted string not properly terminated",
    ]

    async def run(self, engine, pages):
        out = []
        pat = re.compile("|".join(self.ERRORS), re.I)
        for page in pages:
            for param in query_params(page.url):
                test = set_query_param(page.url, param, "'")
                r = await _safe_get(engine, test)
                if r is not None and pat.search(r.text):
                    out.append(self.finding(
                        test, "single quote triggered a SQL error message",
                        param=param,
                        detail="verify manually; confirm with time/boolean payloads"))
        return out


class OpenRedirect(Module):
    VRT_ID = "unvalidated_redirects_and_forwards.open_redirect"
    NAME = "Open redirect"
    DEFAULT_PRIORITY = 4
    PARAMS = {"url", "next", "redirect", "redir", "return", "returnurl",
              "dest", "destination", "continue", "goto", "target"}
    CANARY = "https://vrt-canary.example"

    async def run(self, engine, pages):
        out = []
        for page in pages:
            for param in query_params(page.url):
                if param.lower() not in self.PARAMS:
                    continue
                test = set_query_param(page.url, param, self.CANARY)
                r = await _safe_get(engine, test)
                if r is None:
                    continue
                loc = r.headers.get("location", "")
                if r.status_code in (301, 302, 303, 307, 308) and \
                        loc.startswith(self.CANARY):
                    out.append(self.finding(
                        test, f"redirects to external Location: {loc}",
                        param=param))
        return out


class PathTraversal(Module):
    VRT_ID = "server_side_injection.file_inclusion.local"
    NAME = "Path traversal / local file inclusion"
    DEFAULT_PRIORITY = 2
    PARAMS = {"file", "path", "page", "template", "doc", "document",
              "folder", "root", "pg", "include", "inc", "load"}
    PAYLOAD = "../../../../../../../../etc/passwd"
    SIG = re.compile(r"root:.*:0:0:")

    async def run(self, engine, pages):
        out = []
        for page in pages:
            for param in query_params(page.url):
                if param.lower() not in self.PARAMS:
                    continue
                test = set_query_param(page.url, param, self.PAYLOAD)
                r = await _safe_get(engine, test)
                if r is not None and self.SIG.search(r.text):
                    out.append(self.finding(
                        test, "response contains /etc/passwd contents (root:...:0:0:)",
                        param=param))
        return out


class CORSMisconfig(Module):
    VRT_ID = "server_security_misconfiguration.misconfigured_cors"
    NAME = "CORS: reflects arbitrary Origin with credentials"
    DEFAULT_PRIORITY = 3
    EVIL = "https://vrt-evil.example"

    async def run(self, engine, pages):
        if not pages:
            return []
        r = await _safe_get(engine, pages[0].url,
                            headers={"Origin": self.EVIL})
        if r is None:
            return []
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "").lower()
        if acao == self.EVIL and acac == "true":
            return [self.finding(
                pages[0].url,
                f"reflects Origin {self.EVIL} + Allow-Credentials: true")]
        return []


# --------------------------------------------------------------------------- #
# Active probing of common sensitive paths
# --------------------------------------------------------------------------- #
class SensitiveFiles(Module):
    VRT_ID = "server_security_misconfiguration.exposed_sensitive_files"
    NAME = "Exposed sensitive file"
    DEFAULT_PRIORITY = 2
    PROBES = {
        "/.git/config": "[core]",
        "/.env": "=",
        "/.DS_Store": "Bud1",
        "/config.php.bak": "<?php",
        "/.svn/entries": "",
        "/backup.sql": "",
        "/wp-config.php.bak": "DB_PASSWORD",
        "/phpinfo.php": "phpinfo()",
    }

    async def run(self, engine, pages):
        if not pages:
            return []
        from urllib.parse import urlparse
        p = urlparse(pages[0].url)
        base = f"{p.scheme}://{p.netloc}"
        out = []
        for path, sig in self.PROBES.items():
            r = await _safe_get(engine, base + path)
            if r is None or r.status_code != 200:
                continue
            if sig == "" or sig in r.text:
                out.append(self.finding(
                    base + path,
                    f"HTTP 200 and content signature matched ({sig or 'any'})"))
        return out


# --------------------------------------------------------------------------- #
# NON-automatable VRT classes — stubs kept so the catalog coverage is honest.
# These require app context / human verification; fill in per engagement.
# --------------------------------------------------------------------------- #
class IDORStub(Module):
    VRT_ID = "broken_access_control.idor"
    NAME = "IDOR — MANUAL: needs two accounts / object-id enumeration"
    DEFAULT_PRIORITY = 2

    async def run(self, engine, pages):
        return []  # cannot be judged without role/ownership context


class BusinessLogicStub(Module):
    VRT_ID = "broken_access_control.business_logic"
    NAME = "Business logic — MANUAL: model the intended flow first"
    DEFAULT_PRIORITY = 3

    async def run(self, engine, pages):
        return []


ALL_MODULES: list[Module] = [
    SecurityHeaders(),
    Clickjacking(),
    CookieSecurity(),
    ReflectedXSS(),
    SQLInjection(),
    OpenRedirect(),
    PathTraversal(),
    CORSMisconfig(),
    SensitiveFiles(),
    # manual stubs (run to nothing, but keep VRT coverage visible):
    IDORStub(),
    BusinessLogicStub(),
]
