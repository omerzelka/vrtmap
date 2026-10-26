"""Vulnerability check modules, wired to the official Bugcrowd VRT leaf ids.

Each module declares VRT_IDS: the official leaf id(s) in vrt_catalog/ that it
automates. Every Finding carries the specific leaf id it maps to, and the
orchestrator fills in that leaf's priority from the catalog. Modules whose
leaves are disabled (enabled:false in the catalog file) are skipped, and any
custom `payloads` from those files are injected in addition to the defaults
(available as self.extra_payloads).

To extend: subclass Module, set VRT_IDS, implement run(), append to ALL_MODULES.
"""
from __future__ import annotations

import re

import httpx

from .core import (
    Finding, Page, HttpEngine, OutOfScope, query_params, set_query_param,
)


class Module:
    VRT_IDS: list[str] = []

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


def _similar(a: str, b: str) -> bool:
    """True if two response bodies are ~the same page. Used to detect a
    catch-all / SPA server that answers every path with the same template
    (soft-404), so a 200 is not mistaken for a real file."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return la == lb
    return abs(la - lb) / max(la, lb) < 0.05   # lengths within 5%


async def _submit_form(engine, form, field, payload, filler="vrttest"):
    """Submit `form` with one `field` set to `payload` and the other inputs to
    a harmless filler. GET forms carry the data in the query string, POST forms
    in the request body. Returns the response, or None on error/out-of-scope."""
    from urllib.parse import urlparse, urlencode, urlunparse
    data = {n: (payload if n == field else filler) for n in form.inputs if n}
    try:
        if form.method == "POST":
            return await engine.post(form.action, data=data)
        p = urlparse(form.action)
        return await engine.get(urlunparse(p._replace(query=urlencode(data))))
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
class DescriptiveStackTrace(Module):
    VRT_IDS = ["sensitive_data_exposure.visible_detailed_error_page.descriptive_stack_trace"]
    SIGNATURES = {
        "Python traceback": r"Traceback \(most recent call last\)",
        "Java stack frame": r"\n\s+at \w[\w.$]*(\.\w+)+\([\w.]+\.java:\d+\)",
        "PHP fatal/warning": r"(Fatal error|Warning|Notice):.*?on line \d+",
        "PHP stack trace": r"Stack trace:\s*#0\s",
        ".NET exception": r"System\.\w+(\.\w+)*Exception:",
        ".NET stack frame": r"\n\s+at [\w.]+\(.*\) in .+:line \d+",
        "Node/JS stack frame": r"\n\s+at .+\(.+:\d+:\d+\)",
        "Ruby stack frame": r"\.rb:\d+:in [`']",
    }

    async def run(self, engine, pages):
        out = []
        for page in pages:
            if not page.text:
                continue
            for name, pattern in self.SIGNATURES.items():
                m = re.search(pattern, page.text, re.I)
                if m:
                    snippet = m.group(0).strip().replace("\n", " ")[:120]
                    out.append(self.f(self.VRT_IDS[0], page.url,
                               evidence=f"{name} leaked in response: {snippet!r}"))
                    break      
        return out
    
class ReflectedXSS(Module):
    VRT_IDS = ["cross_site_scripting_xss.reflected.non_self"]
    MARKER = "vrtx9z7q"
    DEFAULT = f"<{MARKER}>"

    async def run(self, engine, pages):
        out = []
        payloads = [self.DEFAULT] + self.extra_payloads
        for page in pages:
            # 1) URL query parameters
            for param in query_params(page.url):
                for pl in payloads:
                    test = set_query_param(page.url, param, pl)
                    r = await _safe_get(engine, test)
                    if r is not None and pl in r.text:
                        out.append(self.f(self.VRT_IDS[0], test,
                                   f"payload '{pl}' reflected unescaped",
                                   param=param))
                        break
            # 2) form fields (GET and POST forms)
            for form in page.forms:
                for field in form.inputs:
                    if not field:
                        continue
                    for pl in payloads:
                        r = await _submit_form(engine, form, field, pl)
                        if r is not None and pl in r.text:
                            out.append(self.f(self.VRT_IDS[0], form.action,
                                       f"payload '{pl}' reflected unescaped via "
                                       f"form field '{field}'",
                                       param=field))
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
            # 1) URL query parameters
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
            # 2) form fields (GET and POST forms)
            for form in page.forms:
                for field in form.inputs:
                    if not field:
                        continue
                    for pl in payloads:
                        r = await _submit_form(engine, form, field, pl)
                        if r is not None and pat.search(r.text):
                            out.append(self.f(self.VRT_IDS[0], form.action,
                                       f"payload '{pl}' triggered a SQL error via "
                                       f"form field '{field}'",
                                       param=field,
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

    BASELINE_PATH = "/vrt9z7q-this-path-should-not-exist"

    async def run(self, engine, pages):
        if not pages:
            return []
        from urllib.parse import urlparse
        p = urlparse(pages[0].url)
        base = f"{p.scheme}://{p.netloc}"
        # soft-404 baseline: how does the server answer a path that cannot exist?
        b = await _safe_get(engine, base + self.BASELINE_PATH)
        base_200 = b is not None and b.status_code == 200
        base_body = b.text if b is not None else ""
        out = []
        for path, sig in self.PROBES.items():
            r = await _safe_get(engine, base + path)
            if r is None or r.status_code != 200:
                continue
            # catch-all / SPA: this path returns the same page as a path that
            # cannot exist -> not a real file, skip (kills the false positive)
            if base_200 and _similar(r.text, base_body):
                continue
            # with a signature: it must be present here AND absent from baseline
            if sig and (sig not in r.text or sig in base_body):
                continue
            out.append(self.f(self.VRT_IDS[0], base + path,
                       "HTTP 200, distinct from soft-404 baseline"
                       + (f", signature '{sig}' matched" if sig else "")))
        return out


class DirectoryListing(Module):
    BASE = "server_security_misconfiguration.directory_listing_enabled"
    VRT_IDS = [f"{BASE}.non_sensitive_data_exposure",
               f"{BASE}.sensitive_data_exposure"]
    # auto-index (directory listing) signatures from common servers
    LISTING = re.compile(
        r"<title>\s*Index of /|<h1>\s*Index of /|"
        r"Directory listing for /|<title>\s*Directory listing for ",
        re.I)
    # file names that make an exposed listing high-severity
    SENSITIVE = re.compile(
        r"\.(sql|bak|old|swp|env|key|pem|pfx|p12|config|ini|log|zip|tar|gz|7z)\b"
        r"|backup|\.git/|\.svn/|id_rsa|\.htpasswd|credential",
        re.I)

    async def run(self, engine, pages):
        from urllib.parse import urlparse
        out = []
        seen = set()
        for page in pages:
            p = urlparse(page.url)
            base = f"{p.scheme}://{p.netloc}"
            segments = [s for s in p.path.split("/") if s]
            count = len(segments) if p.path.endswith("/") else len(segments) - 1
            if count < 0:
                count = 0
            # every ancestor directory: "/", "/a/", "/a/b/" ... (not the file)
            for i in range(count + 1):
                dir_url = base + "/" + "".join(s + "/" for s in segments[:i])
                if dir_url in seen:
                    continue
                seen.add(dir_url)
                r = await _safe_get(engine, dir_url)
                if r is None or r.status_code != 200 or not self.LISTING.search(r.text):
                    continue
                sensitive = bool(self.SENSITIVE.search(r.text))
                leaf = self.VRT_IDS[1] if sensitive else self.VRT_IDS[0]
                out.append(self.f(leaf, dir_url,
                           evidence="server returned an auto-generated directory index"
                                    + (" exposing sensitive files" if sensitive else ""),
                           detail="disable autoindex (Apache: Options -Indexes; "
                                  "nginx: autoindex off)"))
        return out


class SoftwareVersionDisclosure(Module):
    VRT_IDS = ["server_security_misconfiguration.fingerprinting_banner_disclosure"
               ".software_version_in_response_headers"]
    HEADERS = ["server", "x-powered-by", "x-aspnet-version",
               "x-aspnetmvc-version", "x-generator"]
    VERSION = re.compile(r"\d+\.\d+")

    async def run(self, engine, pages):
        if not pages:
            return []
        h = {k.lower(): v for k, v in pages[0].headers.items()}
        out = []
        for name in self.HEADERS:
            val = h.get(name, "")
            if val and self.VERSION.search(val):
                out.append(self.f(self.VRT_IDS[0], pages[0].url,
                           evidence=f"header '{name}: {val}' discloses a software version",
                           param=name))
        return out


class UnsafeHTTPMethods(Module):
    BASE = "server_security_misconfiguration.potentially_unsafe_http_method_enabled"
    VRT_IDS = [f"{BASE}.options", f"{BASE}.trace",
               "cross_site_scripting_xss.trace_method"]

    async def _try(self, engine, method, url):
        try:
            return await engine.request(method, url)
        except (OutOfScope, httpx.HTTPError):
            return None

    async def run(self, engine, pages):
        if not pages:
            return []
        url = pages[0].url
        out = []
        # OPTIONS: does the server advertise its allowed methods?
        r = await self._try(engine, "OPTIONS", url)
        if r is not None:
            allow = r.headers.get("allow", "")
            if allow:
                out.append(self.f(self.VRT_IDS[0], url,
                           evidence=f"OPTIONS enabled; Allow: {allow}"))
        # TRACE: Cross-Site Tracing — the server echoes the request back?
        r = await self._try(engine, "TRACE", url)
        if r is not None and r.status_code == 200 and "TRACE " in r.text:
            out.append(self.f(self.VRT_IDS[1], url,
                       evidence="TRACE method enabled and echoes the request"))
            out.append(self.f(self.VRT_IDS[2], url,
                       evidence="TRACE enabled allows Cross-Site Tracing (XST)"))
        return out


class MixedContent(Module):
    VRT_IDS = ["sensitive_data_exposure.mixed_content"]
    REF = re.compile(r"""(?:src|href)\s*=\s*['"](http://[^'"]+)['"]""", re.I)

    async def run(self, engine, pages):
        out = []
        for page in pages:
            if not page.url.startswith("https://") or not page.text:
                continue
            m = self.REF.search(page.text)
            if m:
                out.append(self.f(self.VRT_IDS[0], page.url,
                           evidence=f"HTTPS page loads insecure resource over HTTP: "
                                    f"{m.group(1)[:120]}"))
        return out


class InsecureFormTransport(Module):
    VRT_IDS = ["insecure_data_transport.cleartext_transmission_of_sensitive_data"]
    SENS = re.compile(r"pass|pwd|card|cvv|cvc|ssn|secret|token|otp", re.I)

    async def run(self, engine, pages):
        out = []
        for page in pages:
            for form in page.forms:
                over_http = page.url.startswith("http://") \
                    or form.action.startswith("http://")
                if not over_http:
                    continue
                sens = [n for n in form.inputs if n and self.SENS.search(n)]
                if sens:
                    out.append(self.f(self.VRT_IDS[0], page.url,
                               evidence=f"form posts sensitive field(s) {sens} "
                                        f"over cleartext HTTP",
                               param=form.action))
        return out


class RobotsDisclosure(Module):
    VRT_IDS = ["sensitive_data_exposure.disclosure_of_secrets.publicly_accessible_robots"]
    INTERESTING = re.compile(
        r"admin|backup|config|secret|private|internal|\.git|\bdb\b|sql|"
        r"password|api[_-]?key|token|staging|\btest\b",
        re.I)

    async def run(self, engine, pages):
        if not pages:
            return []
        from urllib.parse import urlparse
        p = urlparse(pages[0].url)
        url = f"{p.scheme}://{p.netloc}/robots.txt"
        r = await _safe_get(engine, url)
        if r is None or r.status_code != 200:
            return []
        hits = [line.strip() for line in r.text.splitlines()
                if line.lower().startswith("disallow") and self.INTERESTING.search(line)]
        if hits:
            return [self.f(self.VRT_IDS[0], url,
                    evidence=f"robots.txt exposes sensitive paths: {hits[:5]}")]
        return []


class PasswordAutocomplete(Module):
    VRT_IDS = ["external_behavior.browser_feature.autocomplete_enabled"]
    PW_INPUT = re.compile(r"<input\b[^>]*type\s*=\s*['\"]password['\"][^>]*>", re.I)
    AUTOCOMPLETE_OFF = re.compile(r"autocomplete\s*=\s*['\"]off['\"]", re.I)

    async def run(self, engine, pages):
        out = []
        for page in pages:
            if not page.text:
                continue
            for tag in self.PW_INPUT.findall(page.text):
                if not self.AUTOCOMPLETE_OFF.search(tag):
                    out.append(self.f(self.VRT_IDS[0], page.url,
                               evidence="password field without autocomplete=off"))
                    break
        return out


class SensitivePageCaching(Module):
    VRT_IDS = ["server_security_misconfiguration.lack_of_security_headers"
               ".cache_control_for_a_sensitive_page"]
    PW = re.compile(r"type\s*=\s*['\"]password['\"]", re.I)

    async def run(self, engine, pages):
        out = []
        for page in pages:
            if not page.text or not self.PW.search(page.text):
                continue
            h = {k.lower(): v for k, v in page.headers.items()}
            cc = h.get("cache-control", "").lower()
            if "no-store" not in cc and "private" not in cc:
                out.append(self.f(self.VRT_IDS[0], page.url,
                           evidence=f"sensitive page (password field) with weak "
                                    f"Cache-Control: '{cc or 'absent'}'"))
        return out


class MailSpoofing(Module):
    """Email-spoofing exposure for the target's domain, via DNS. Needs
    dnspython (optional). Checks for SPF and DMARC records: a domain with no
    SPF and no DMARC can be spoofed; a domain with no DMARC (or DMARC p=none)
    lets spoofed mail reach the inbox."""
    VRT_IDS = [
        "server_security_misconfiguration.mail_server_misconfiguration"
        ".no_spoofing_protection_on_email_domain",
        "server_security_misconfiguration.mail_server_misconfiguration"
        ".email_spoofing_to_inbox_due_to_missing_or_misconfigured_dmarc_on_email_domain",
    ]

    async def run(self, engine, pages):
        if not pages:
            return []
        try:
            import dns.resolver  # noqa: F401
        except ImportError:
            return []            # dnspython not installed -> silently skip
        import asyncio
        from urllib.parse import urlparse
        host = (urlparse(pages[0].url).hostname or "").lower()
        labels = host.split(".")
        if len(labels) < 2 or host.replace(".", "").isdigit():
            return []            # IP address or localhost -> no email domain
        domain = ".".join(labels[-2:])
        spf, dmarc = await asyncio.to_thread(self._lookup, domain)
        if spf is None and dmarc is None:
            return [self.f(self.VRT_IDS[0], f"dns://{domain}",
                    evidence="no SPF and no DMARC record — domain is spoofable")]
        if dmarc is None or "p=none" in (dmarc or "").replace(" ", "").lower():
            reason = "no DMARC record" if dmarc is None else "DMARC policy is p=none"
            return [self.f(self.VRT_IDS[1], f"dns://{domain}",
                    evidence=f"{reason}; spoofed mail can reach the inbox")]
        return []

    @staticmethod
    def _lookup(domain):
        import dns.resolver

        def txt(name):
            try:
                ans = dns.resolver.resolve(name, "TXT", lifetime=5)
                return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
            except Exception:
                return []
        spf = next((t for t in txt(domain)
                    if t.lower().startswith("v=spf1")), None)
        dmarc = next((t for t in txt("_dmarc." + domain)
                      if t.lower().startswith("v=dmarc1")), None)
        return spf, dmarc


class CSRFTokenMissing(Module):
    VRT_IDS = ["cross_site_request_forgery_csrf.application_wide"]
    TOKEN = re.compile(r"csrf|xsrf|authenticity|nonce|_token|anti.?forgery", re.I)

    async def run(self, engine, pages):
        out = []
        for page in pages:
            for form in page.forms:
                if form.method != "POST":
                    continue
                if any(n and self.TOKEN.search(n) for n in form.inputs):
                    continue
                fields = ",".join(n for n in form.inputs if n)
                out.append(self.f(self.VRT_IDS[0], form.action,
                           evidence="POST form has no anti-CSRF token field",
                           param=fields or None))
        return out


class InternalIPDisclosure(Module):
    VRT_IDS = ["sensitive_data_exposure.internal_ip_disclosure"]
    # RFC 1918 private ranges (loopback 127.x is intentionally excluded)
    PRIV = re.compile(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")

    async def run(self, engine, pages):
        out = []
        for page in pages:
            if not page.text:
                continue
            m = self.PRIV.search(page.text)
            if m:
                out.append(self.f(self.VRT_IDS[0], page.url,
                           evidence=f"response discloses a private/internal IP: "
                                    f"{m.group(1)}"))
        return out


class MissingSubresourceIntegrity(Module):
    VRT_IDS = ["server_security_misconfiguration.missing_subresource_integrity"]
    SCRIPT = re.compile(
        r"<script\b[^>]*\bsrc\s*=\s*['\"](https?://[^'\"]+)['\"][^>]*>", re.I)
    INTEGRITY = re.compile(r"\bintegrity\s*=", re.I)

    async def run(self, engine, pages):
        from urllib.parse import urlparse
        out = []
        for page in pages:
            if not page.text:
                continue
            host = urlparse(page.url).hostname or ""
            for m in self.SCRIPT.finditer(page.text):
                src = m.group(1)
                if (urlparse(src).hostname or "") == host:
                    continue   # same-origin script — SRI not expected
                if not self.INTEGRITY.search(m.group(0)):
                    out.append(self.f(self.VRT_IDS[0], page.url,
                               evidence=f"external script without Subresource "
                                        f"Integrity: {src[:120]}",
                               param=src))
                    break
        return out


class RefererXSS(Module):
    VRT_IDS = ["cross_site_scripting_xss.referer"]
    MARKER = "vrtref9z7q"

    async def run(self, engine, pages):
        out = []
        payload = f"<{self.MARKER}>"
        for page in pages:
            r = await _safe_get(engine, page.url, headers={"Referer": payload})
            if r is not None and payload in r.text:
                out.append(self.f(self.VRT_IDS[0], page.url,
                           evidence="Referer header reflected unescaped"))
                break
        return out


class LoginOverHTTP(Module):
    VRT_IDS = [
        "broken_authentication_and_session_management.weak_login_function.over_http",
        "broken_authentication_and_session_management.weak_registration_implementation.over_http",
    ]
    PW = re.compile(r"type\s*=\s*['\"]password['\"]", re.I)
    REG = re.compile(r"regist|sign.?up|create.?account", re.I)

    async def run(self, engine, pages):
        out = []
        for page in pages:
            if not page.url.startswith("http://") or not page.text:
                continue
            if not self.PW.search(page.text):
                continue
            is_reg = bool(self.REG.search(page.text) or self.REG.search(page.url))
            leaf = self.VRT_IDS[1] if is_reg else self.VRT_IDS[0]
            out.append(self.f(leaf, page.url,
                       evidence="password form served over cleartext HTTP"))
        return out


class SessionTokenCleartext(Module):
    VRT_IDS = ["broken_authentication_and_session_management"
               ".cleartext_transmission_of_session_token"]
    SESSIONISH = re.compile(r"sess|sid|token|auth|jwt|login", re.I)

    async def run(self, engine, pages):
        out = []
        for page in pages:
            if not page.url.startswith("http://"):
                continue
            r = await _safe_get(engine, page.url)
            if r is None:
                continue
            for raw in r.headers.get_list("set-cookie"):
                name = raw.split("=", 1)[0].strip()
                if self.SESSIONISH.search(name) and "secure" not in raw.lower():
                    out.append(self.f(self.VRT_IDS[0], page.url,
                               f"session cookie '{name}' set over HTTP without Secure",
                               param=name))
            if out:
                break
        return out


class ExtraSecurityHeaders(Module):
    BASE = "server_security_misconfiguration.lack_of_security_headers"
    VRT_IDS = [f"{BASE}.x_frame_options", f"{BASE}.x_xss_protection",
               f"{BASE}.content_security_policy_report_only"]

    async def run(self, engine, pages):
        if not pages:
            return []
        h = {k.lower(): v for k, v in pages[0].headers.items()}
        out = []
        if "x-frame-options" not in h:
            out.append(self.f(self.VRT_IDS[0], pages[0].url,
                       evidence="X-Frame-Options header absent"))
        if "x-xss-protection" not in h:
            out.append(self.f(self.VRT_IDS[1], pages[0].url,
                       evidence="X-XSS-Protection header absent"))
        if "content-security-policy" not in h and \
                "content-security-policy-report-only" in h:
            out.append(self.f(self.VRT_IDS[2], pages[0].url,
                       evidence="CSP is report-only (not enforced)"))
        return out


class InsecureCSP(Module):
    VRT_IDS = ["server_security_misconfiguration.misconfigured_security_headers.insecure_csp"]

    async def run(self, engine, pages):
        if not pages:
            return []
        h = {k.lower(): v for k, v in pages[0].headers.items()}
        csp = h.get("content-security-policy", "")
        if not csp:
            return []
        low = csp.lower()
        bad = [t for t in ("unsafe-inline", "unsafe-eval") if t in low]
        if "*" in csp or bad:
            return [self.f(self.VRT_IDS[0], pages[0].url,
                    evidence=f"weak CSP directives: {bad or ['wildcard *']}")]
        return []


class CookieScope(Module):
    VRT_IDS = ["server_security_misconfiguration.cookie_scoped_to_parent_domain"]

    async def run(self, engine, pages):
        if not pages:
            return []
        r = await _safe_get(engine, pages[0].url)
        if r is None:
            return []
        out = []
        for raw in r.headers.get_list("set-cookie"):
            m = re.search(r"domain=\s*(\.[^;\s]+)", raw, re.I)
            if m:
                name = raw.split("=", 1)[0].strip()
                out.append(self.f(self.VRT_IDS[0], pages[0].url,
                           f"cookie '{name}' scoped to parent domain {m.group(1)}",
                           param=name))
        return out


class ExposedAdminPortal(Module):
    """Probe common admin/management portal paths. Uses the same soft-404
    baseline trick as SensitiveFiles so a catch-all server doesn't cause false
    positives."""
    BASE = "server_security_misconfiguration.exposed_portal"
    VRT_IDS = [f"{BASE}.admin_portal", f"{BASE}.non_admin_portal"]
    ADMIN = ["/admin", "/administrator", "/admin/login", "/wp-admin/",
             "/wp-login.php", "/phpmyadmin/", "/manager/html", "/cpanel",
             "/console", "/jenkins/", "/.git/"]
    USER = ["/user/login", "/account/login", "/portal"]
    LOGINISH = re.compile(r"login|sign.?in|password|username|dashboard|admin", re.I)
    BASELINE_PATH = "/vrt9z7q-not-a-real-portal"

    async def run(self, engine, pages):
        if not pages:
            return []
        from urllib.parse import urlparse
        p = urlparse(pages[0].url)
        base = f"{p.scheme}://{p.netloc}"
        b = await _safe_get(engine, base + self.BASELINE_PATH)
        base_200 = b is not None and b.status_code == 200
        base_body = b.text if b is not None else ""
        out = []
        for path, leaf in ([(x, self.VRT_IDS[0]) for x in self.ADMIN]
                           + [(x, self.VRT_IDS[1]) for x in self.USER]):
            r = await _safe_get(engine, base + path)
            if r is None or r.status_code not in (200, 401, 403):
                continue
            if r.status_code == 200:
                if base_200 and _similar(r.text, base_body):
                    continue          # catch-all page, not a real portal
                if not self.LOGINISH.search(r.text):
                    continue
            out.append(self.f(leaf, base + path,
                       f"portal reachable (HTTP {r.status_code})"))
        return out


class TLSInspection(Module):
    """TLS/SSL posture of the target (stdlib ssl — no extra dependency).
    Flags a certificate error, an obsolete protocol, a weak cipher, and the
    lack of forward secrecy."""
    BASE = "server_security_misconfiguration"
    VRT_IDS = [f"{BASE}.insecure_ssl.certificate_error",
               f"{BASE}.ssl_attack_breach_poodle_etc",
               f"{BASE}.insecure_ssl.insecure_cipher_suite",
               f"{BASE}.insecure_ssl.lack_of_forward_secrecy"]
    OLD_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
    WEAK_CIPHER = re.compile(r"RC4|3DES|\bDES\b|NULL|EXPORT|MD5", re.I)

    async def run(self, engine, pages):
        import asyncio
        host, port = self._target(engine, pages)
        if not host:
            return []
        info = await asyncio.to_thread(self._probe, host, port)
        if info is None:
            return []
        where = f"https://{host}:{port}"
        out = []
        if info["cert_error"]:
            out.append(self.f(self.VRT_IDS[0], where,
                       f"TLS certificate error: {info['cert_error'][:120]}"))
        if info["proto"] in self.OLD_PROTOCOLS:
            out.append(self.f(self.VRT_IDS[1], where,
                       f"obsolete TLS protocol negotiated: {info['proto']}"))
        name = (info["cipher"] or [""])[0] or ""
        if name and self.WEAK_CIPHER.search(name):
            out.append(self.f(self.VRT_IDS[2], where,
                       f"weak cipher negotiated: {name}"))
        if name and "ECDHE" not in name.upper() and "DHE" not in name.upper():
            out.append(self.f(self.VRT_IDS[3], where,
                       f"cipher without forward secrecy: {name}"))
        return out

    @staticmethod
    def _target(engine, pages):
        from urllib.parse import urlparse
        if pages:
            p = urlparse(pages[0].url)
            if p.scheme == "https":
                return p.hostname, (p.port or 443)
        host = next(iter(engine.scope.allowed), None) if engine else None
        return host, 443

    @staticmethod
    def _probe(host, port):
        import ssl
        import socket
        cert_error = None
        proto = cipher = None
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=6) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    proto, cipher = ss.version(), ss.cipher()
        except ssl.SSLCertVerificationError as e:
            cert_error = str(e)
        except (ssl.SSLError, OSError):
            pass
        if cert_error is not None or proto is None:
            try:
                ctx = ssl._create_unverified_context()
                with socket.create_connection((host, port), timeout=6) as s:
                    with ctx.wrap_socket(s, server_hostname=host) as ss:
                        proto, cipher = ss.version(), ss.cipher()
            except (ssl.SSLError, OSError):
                if cert_error is None and proto is None:
                    return None
        return {"cert_error": cert_error, "proto": proto, "cipher": cipher}


class DNSMisconfig(Module):
    """DNS hygiene for the target's domain (dnspython, optional): missing CAA
    record, DNSSEC not enabled, and AXFR zone transfer allowed."""
    BASE = "server_security_misconfiguration"
    VRT_IDS = [f"{BASE}.misconfigured_dns.missing_caa_record",
               f"{BASE}.missing_dnssec",
               f"{BASE}.misconfigured_dns.zone_transfer"]

    async def run(self, engine, pages):
        if not pages:
            return []
        try:
            import dns.resolver  # noqa: F401
        except ImportError:
            return []
        import asyncio
        from urllib.parse import urlparse
        host = (urlparse(pages[0].url).hostname or "").lower()
        labels = host.split(".")
        if len(labels) < 2 or host.replace(".", "").isdigit():
            return []
        domain = ".".join(labels[-2:])
        return await asyncio.to_thread(self._checks, domain)

    def _checks(self, domain):
        import dns.resolver
        import dns.query
        import dns.zone
        out = []

        def has(name, rtype):
            try:
                dns.resolver.resolve(name, rtype, lifetime=5)
                return True
            except Exception:
                return False

        if not has(domain, "CAA"):
            out.append(self.f(self.VRT_IDS[0], f"dns://{domain}",
                       "no CAA record — any CA may issue certs for this domain"))
        if not has(domain, "DNSKEY"):
            out.append(self.f(self.VRT_IDS[1], f"dns://{domain}",
                       "no DNSKEY — DNSSEC not enabled"))
        try:
            ns = [str(r.target).rstrip(".")
                  for r in dns.resolver.resolve(domain, "NS", lifetime=5)]
        except Exception:
            ns = []
        for nsname in ns[:4]:
            try:
                ip = str(dns.resolver.resolve(nsname, "A", lifetime=5)[0])
                if dns.zone.from_xfr(dns.query.xfr(ip, domain, lifetime=8)):
                    out.append(self.f(self.VRT_IDS[2], f"dns://{domain}",
                               f"zone transfer (AXFR) allowed from {nsname}"))
                    break
            except Exception:
                continue
        return out


ALL_MODULES: list[Module] = [
    # passive config / header checks
    SecurityHeaders(),
    Clickjacking(),
    CookieSecurity(),
    SoftwareVersionDisclosure(),
    MixedContent(),
    InsecureFormTransport(),
    PasswordAutocomplete(),
    SensitivePageCaching(),
    DescriptiveStackTrace(),
    CSRFTokenMissing(),
    InternalIPDisclosure(),
    MissingSubresourceIntegrity(),
    MailSpoofing(),
    ExtraSecurityHeaders(),
    InsecureCSP(),
    LoginOverHTTP(),
    # active probes
    ReflectedXSS(),
    SQLInjection(),
    OpenRedirect(),
    PathTraversal(),
    CORSMisconfig(),
    SensitiveFiles(),
    DirectoryListing(),
    UnsafeHTTPMethods(),
    RobotsDisclosure(),
    RefererXSS(),
    SessionTokenCleartext(),
    CookieScope(),
    TLSInspection(),
    DNSMisconfig(),
    ExposedAdminPortal(),
]
