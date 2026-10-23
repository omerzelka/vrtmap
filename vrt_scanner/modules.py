"""Vulnerability check modules, wired to the official Bugcrowd VRT leaf ids.

Each module declares VRT_IDS: the official leaf id(s) in vrt_catalog/ that it
automates. Every Finding carries the specific leaf id it maps to, and the
orchestrator fills in that leaf's priority from the catalog. Modules whose
leaves are disabled (enabled:false in the catalog file) are skipped, and any
custom `payloads` from those files are injected in addition to the defaults
(available as self.extra_payloads).

To extend: subclass Module, set VRT_IDS, implement run(), append to
ALL_MODULES. Set MANUAL=True for classes that can't be auto-detected (they are
counted as manual coverage, not automated, and are not executed).
"""
from __future__ import annotations

import re

import httpx

from .core import (
    Finding, Page, HttpEngine, OutOfScope, query_params, set_query_param,
)


class Module:
    VRT_IDS: list[str] = []
    MANUAL: bool = False

    def __init__(self):
        self.extra_payloads: list[str] = []   # filled from catalog by orchestrator

    async def run(self, engine: HttpEngine, pages: list[Page]) -> list[Finding]:
        raise NotImplementedError

    @staticmethod
    def f(vrt_id, url, evidence, param=None, detail="") -> Finding:
        # priority is assigned later from the catalog leaf
        return Finding(vrt_id=vrt_id, title="", url=url, evidence=evidence,
                       param=param, detail=detail)


async def _safe_get(engine, url, **kw):
    try:
        return await engine.get(url, **kw)
    except (OutOfScope, httpx.HTTPError):
        return None


# --------------------------------------------------------------------------- #
# Passive header / config checks
# --------------------------------------------------------------------------- #
class SecurityHeaders(Module):
    PREFIX = "server_security_misconfiguration.lack_of_security_headers"
    # response header -> official VRT leaf suffix
    HEADERS = {
        "content-security-policy": "content_security_policy",
        "strict-transport-security": "strict_transport_security",
        "x-content-type-options": "x_content_type_options",
    }
    VRT_IDS = [
        "server_security_misconfiguration.lack_of_security_headers.content_security_policy",
        "server_security_misconfiguration.lack_of_security_headers.strict_transport_security",
        "server_security_misconfiguration.lack_of_security_headers.x_content_type_options",
    ]

    async def run(self, engine, pages):
        out = []
        if not pages:
            return out
        h = {k.lower(): v for k, v in pages[0].headers.items()}
        for header, suffix in self.HEADERS.items():
            if header not in h:
                out.append(self.f(f"{self.PREFIX}.{suffix}", pages[0].url,
                                  evidence=f"response header '{header}' absent"))
        return out


class Clickjacking(Module):
    VRT_IDS = ["server_security_misconfiguration.clickjacking.non_sensitive_action"]

    async def run(self, engine, pages):
        if not pages:
            return []
        h = {k.lower(): v for k, v in pages[0].headers.items()}
        csp = h.get("content-security-policy", "")
        if "x-frame-options" not in h and "frame-ancestors" not in csp:
            return [self.f(self.VRT_IDS[0], pages[0].url,
                    "neither X-Frame-Options nor CSP frame-ancestors present",
                    detail="if the page performs a sensitive action, re-map to "
                           ".sensitive_action")]
        return []


class CookieSecurity(Module):
    BASE = "server_security_misconfiguration.missing_secure_or_httponly_cookie_flag"
    VRT_IDS = [f"{BASE}.session_token", f"{BASE}.non_session_cookie"]
    SESSIONISH = re.compile(r"sess|sid|token|auth|jwt|login|csrf", re.I)

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
            if not missing:
                continue
            leaf = f"{self.BASE}.session_token" if self.SESSIONISH.search(name) \
                else f"{self.BASE}.non_session_cookie"
            out.append(self.f(leaf, pages[0].url,
                       f"cookie '{name}' missing flag(s): {', '.join(missing)}",
                       param=name))
        return out


# --------------------------------------------------------------------------- #
# Active injection checks
# --------------------------------------------------------------------------- #
class ReflectedXSS(Module):
    VRT_IDS = ["cross_site_scripting_xss.reflected.non_self"]
    MARKER = "vrtx9z7q"
    DEFAULT = f"<{MARKER}>"

    async def run(self, engine, pages):
        out = []
        payloads = [self.DEFAULT] + self.extra_payloads
        for page in pages:
            for param in query_params(page.url):
                for pl in payloads:
                    test = set_query_param(page.url, param, pl)
                    r = await _safe_get(engine, test)
                    if r is not None and pl in r.text:
                        out.append(self.f(self.VRT_IDS[0], test,
                                   f"payload '{pl}' reflected unescaped",
                                   param=param))
                        break
        return out


class SQLInjection(Module):
    VRT_IDS = ["server_side_injection.sql_injection"]
    DEFAULT = ["'"]
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
        payloads = self.DEFAULT + self.extra_payloads
        for page in pages:
            for param in query_params(page.url):
                for pl in payloads:
                    test = set_query_param(page.url, param, pl)
                    r = await _safe_get(engine, test)
                    if r is not None and pat.search(r.text):
                        out.append(self.f(self.VRT_IDS[0], test,
                                   f"payload '{pl}' triggered a SQL error",
                                   param=param,
                                   detail="confirm with boolean/time-based payloads"))
                        break
        return out


class OpenRedirect(Module):
    VRT_IDS = ["unvalidated_redirects_and_forwards.open_redirect.get_based"]
    PARAMS = {"url", "next", "redirect", "redir", "return", "returnurl",
              "dest", "destination", "continue", "goto", "target"}
    DEFAULT = ["https://vrt-canary.example"]

    async def run(self, engine, pages):
        out = []
        payloads = self.DEFAULT + self.extra_payloads
        for page in pages:
            for param in query_params(page.url):
                if param.lower() not in self.PARAMS:
                    continue
                for pl in payloads:
                    test = set_query_param(page.url, param, pl)
                    r = await _safe_get(engine, test)
                    if r is None:
                        continue
                    loc = r.headers.get("location", "")
                    if r.status_code in (301, 302, 303, 307, 308) and \
                            loc.startswith(pl.split("?")[0][:24]):
                        out.append(self.f(self.VRT_IDS[0], test,
                                   f"redirects to external Location: {loc}",
                                   param=param))
                        break
        return out


class PathTraversal(Module):
    VRT_IDS = ["server_side_injection.file_inclusion.local"]
    PARAMS = {"file", "path", "page", "template", "doc", "document",
              "folder", "root", "pg", "include", "inc", "load"}
    DEFAULT = ["../../../../../../../../etc/passwd"]
    SIG = re.compile(r"root:.*:0:0:")

    async def run(self, engine, pages):
        out = []
        payloads = self.DEFAULT + self.extra_payloads
        for page in pages:
            for param in query_params(page.url):
                if param.lower() not in self.PARAMS:
                    continue
                for pl in payloads:
                    test = set_query_param(page.url, param, pl)
                    r = await _safe_get(engine, test)
                    if r is not None and self.SIG.search(r.text):
                        out.append(self.f(self.VRT_IDS[0], test,
                                   "response contains /etc/passwd (root:...:0:0:)",
                                   param=param))
                        break
        return out


class CORSMisconfig(Module):
    VRT_IDS = ["server_security_misconfiguration.unsafe_cross_origin_resource_sharing"]
    EVIL = "https://vrt-evil.example"

    async def run(self, engine, pages):
        if not pages:
            return []
        r = await _safe_get(engine, pages[0].url, headers={"Origin": self.EVIL})
        if r is None:
            return []
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "").lower()
        if acao == self.EVIL and acac == "true":
            return [self.f(self.VRT_IDS[0], pages[0].url,
                    f"reflects Origin {self.EVIL} + Allow-Credentials: true")]
        return []


class SensitiveFiles(Module):
    VRT_IDS = ["sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset"]
    PROBES = {
        "/.git/config": "[core]",
        "/.env": "=",
        "/config.php.bak": "<?php",
        "/.svn/entries": "",
        "/backup.sql": "",
        "/wp-config.php.bak": "DB_PASSWORD",
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
                out.append(self.f(self.VRT_IDS[0], base + path,
                           f"HTTP 200 + content signature matched ({sig or 'any'})"))
        return out


# --------------------------------------------------------------------------- #
# MANUAL classes — real VRT leaves that need app context + human verification.
# Counted as "manual" coverage, never auto-run.
# --------------------------------------------------------------------------- #
class IDORManual(Module):
    MANUAL = True
    VRT_IDS = [
        "broken_access_control.idor.view_sensitive_information_iterable_object_identifiers",
        "broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers",
        "broken_access_control.idor.modify_view_sensitive_information_guid",
        "broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers",
        "broken_access_control.idor.view_non_sensitive_information",
    ]

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
    IDORManual(),   # manual-only
]
