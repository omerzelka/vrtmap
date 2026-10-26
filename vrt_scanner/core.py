"""Core engine: data models, scope/authorization gate, HTTP engine, crawler,
VRT catalog loader, URL helpers and the reporter.

Everything the scanner needs that is not a specific vulnerability check lives
here so the module files stay small and focused on detection logic.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import (
    urlparse, urljoin, urldefrag, urlencode, urlunparse, parse_qsl,
)

try:
    import httpx
except ImportError as e:  # pragma: no cover
    raise SystemExit("Missing dependency: pip install httpx beautifulsoup4") from e
try:
    from bs4 import BeautifulSoup
except ImportError as e:  # pragma: no cover
    raise SystemExit("Missing dependency: pip install httpx beautifulsoup4") from e


# --------------------------------------------------------------------------- #
# Data models
# --------------------------------------------------------------------------- #
PRIORITY_LABELS = {1: "P1 Critical", 2: "P2 High", 3: "P3 Medium",
                   4: "P4 Low", 5: "P5 Info"}


@dataclass
class Finding:
    vrt_id: str
    title: str
    url: str
    evidence: str
    priority: int = 3
    param: str | None = None
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "vrt_id": self.vrt_id,
            "title": self.title,
            "priority": self.priority,
            "priority_label": PRIORITY_LABELS.get(self.priority, "?"),
            "url": self.url,
            "param": self.param,
            "evidence": self.evidence,
            "detail": self.detail,
        }


@dataclass
class Form:
    method: str
    action: str
    inputs: list[str]


@dataclass
class Page:
    url: str
    status: int
    headers: dict
    text: str
    forms: list[Form] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


class OutOfScope(Exception):
    """Raised when a request targets a host outside the authorized scope."""


# --------------------------------------------------------------------------- #
# Scope / authorization gate
# --------------------------------------------------------------------------- #
class Scope:
    """Whitelist of hosts the scanner is allowed to touch. A request to any
    other host raises OutOfScope. This is the safety boundary: the scanner
    only acts on targets you explicitly authorized."""

    def __init__(self, allowed_hosts: list[str]):
        self.allowed = {h.lower().strip() for h in allowed_hosts if h.strip()}

    def allows(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        return any(host == a or host.endswith("." + a) for a in self.allowed)


# --------------------------------------------------------------------------- #
# HTTP engine (rate-limited, scope-enforced, concurrency-capped)
# --------------------------------------------------------------------------- #
class HttpEngine:
    def __init__(self, scope: Scope, rate: float = 5.0, concurrency: int = 5,
                 timeout: float = 10.0, verify_tls: bool = True,
                 user_agent: str = "vrt-scanner/0.1 (authorized-testing)"):
        self.scope = scope
        self._sem = asyncio.Semaphore(max(1, concurrency))
        self._delay = (1.0 / rate) if rate and rate > 0 else 0.0
        self._last = 0.0
        self.requests_made = 0
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,          # we inspect Location ourselves
            verify=verify_tls,
            headers={"User-Agent": user_agent},
        )

    async def request(self, method: str, url: str, **kw) -> httpx.Response:
        if not self.scope.allows(url):
            raise OutOfScope(url)
        async with self._sem:
            if self._delay:
                wait = self._delay - (time.monotonic() - self._last)
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last = time.monotonic()
            self.requests_made += 1
            return await self.client.request(method, url, **kw)

    async def get(self, url: str, **kw) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> httpx.Response:
        return await self.request("POST", url, **kw)

    async def aclose(self):
        await self.client.aclose()


# --------------------------------------------------------------------------- #
# URL / form helpers
# --------------------------------------------------------------------------- #
def query_params(url: str) -> list[str]:
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def set_query_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    out = [(k, (value if k == name else v)) for k, v in pairs]
    return urlunparse(p._replace(query=urlencode(out)))


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


# --------------------------------------------------------------------------- #
# Crawler
# --------------------------------------------------------------------------- #
class Crawler:
    def __init__(self, engine: HttpEngine, max_pages: int = 50):
        self.engine = engine
        self.max_pages = max_pages

    @staticmethod
    def _parse_forms(soup: BeautifulSoup, base: str) -> list[Form]:
        forms = []
        for f in soup.find_all("form"):
            action = urljoin(base, f.get("action") or base)
            method = (f.get("method") or "GET").upper()
            names = [i.get("name") for i in f.find_all(["input", "textarea", "select"])
                     if i.get("name")]
            forms.append(Form(method=method, action=action, inputs=names))
        return forms

    async def _seed(self, start_url: str) -> list[str]:
        """Discover extra entry points from robots.txt and sitemap.xml so the
        crawl is not limited to links found on the start page. Returns only
        in-scope, same-origin URLs."""
        p = urlparse(start_url)
        base = f"{p.scheme}://{p.netloc}"
        found: list[str] = []
        sitemaps = [f"{base}/sitemap.xml"]
        # robots.txt: Allow/Disallow paths + Sitemap: declarations
        try:
            r = await self.engine.get(f"{base}/robots.txt")
            if r.status_code == 200 and "html" not in r.headers.get("content-type", ""):
                for line in r.text.splitlines():
                    line = line.strip()
                    low = line.lower()
                    if low.startswith(("allow:", "disallow:")):
                        path = line.split(":", 1)[1].strip()
                        if path.startswith("/") and "*" not in path:
                            found.append(base + path)
                    elif low.startswith("sitemap:"):
                        sm = line.split(":", 1)[1].strip()
                        if sm.startswith("http"):
                            sitemaps.append(sm)
        except (OutOfScope, httpx.HTTPError):
            pass
        # sitemap.xml: <loc>URL</loc> entries
        for sm in sitemaps:
            try:
                r = await self.engine.get(sm)
            except (OutOfScope, httpx.HTTPError):
                continue
            if r.status_code == 200:
                found += re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text, re.I)
        # keep only in-scope, same-origin URLs (cap to avoid a huge sitemap flood)
        out = []
        for u in found[:300]:
            u = urldefrag(u).url
            if same_origin(u, start_url) and self.engine.scope.allows(u):
                out.append(u)
        return out

    async def crawl(self, start_url: str) -> list[Page]:
        queue = [start_url] + await self._seed(start_url)
        seen: set[str] = set()
        pages: list[Page] = []
        while queue and len(pages) < self.max_pages:
            url = urldefrag(queue.pop(0)).url
            if url in seen:
                continue
            seen.add(url)
            try:
                r = await self.engine.get(url)
            except (OutOfScope, httpx.HTTPError):
                continue
            ctype = r.headers.get("content-type", "")
            text = r.text if "html" in ctype or not ctype else ""
            soup = BeautifulSoup(text, "html.parser") if text else BeautifulSoup("", "html.parser")
            forms = self._parse_forms(soup, url)
            links = []
            for a in soup.find_all("a", href=True):
                nxt = urldefrag(urljoin(url, a["href"])).url
                if nxt.startswith("http") and same_origin(nxt, start_url):
                    links.append(nxt)
                    if nxt not in seen and self.engine.scope.allows(nxt):
                        queue.append(nxt)
            pages.append(Page(url=url, status=r.status_code,
                              headers=dict(r.headers), text=text,
                              forms=forms, links=links))
        return pages


# --------------------------------------------------------------------------- #
# VRT catalog
# --------------------------------------------------------------------------- #
class VRTCatalog:
    """The VRT taxonomy. Two sources are supported:

    * load_dir() — the exploded per-leaf catalog under vrt_catalog/ (via its
      index.json). This is the source of truth; it also exposes each leaf's
      editable config (enabled / payloads / notes) through leaf_config().
    * load() — a single official-shape VRT JSON ({content:[{id,name,priority,
      children}]}), kept for compatibility.
    """

    def __init__(self, flat: dict[str, dict], directory: Path | None = None):
        self.flat = flat
        self.dir = directory
        self._cfg_cache: dict[str, dict] = {}

    @classmethod
    def load(cls, path: str | Path) -> "VRTCatalog":
        data = json.loads(Path(path).read_text())
        flat: dict[str, dict] = {}

        def walk(nodes, prefix, inherited):
            for n in nodes:
                nid = f"{prefix}.{n['id']}" if prefix else n["id"]
                prio = n.get("priority") if n.get("priority") is not None else inherited
                children = n.get("children") or []
                if children:
                    walk(children, nid, prio)
                else:
                    flat[nid] = {"name": n.get("name", nid), "priority": prio or 3}
        walk(data.get("content", []), "", None)
        return cls(flat)

    @classmethod
    def load_dir(cls, directory: str | Path) -> "VRTCatalog":
        directory = Path(directory)
        index = json.loads((directory / "index.json").read_text())
        flat = {e["vrt_id"]: {"name": e["name"],
                              "priority": e.get("priority") or 3,
                              "file": e["file"]}
                for e in index}
        return cls(flat, directory=directory)

    def info(self, vrt_id: str) -> dict | None:
        return self.flat.get(vrt_id)

    def leaf_config(self, vrt_id: str) -> dict:
        """Per-leaf editable config from the exploded file: enabled / payloads
        / notes. Defaults to enabled when the file or field is missing."""
        if vrt_id in self._cfg_cache:
            return self._cfg_cache[vrt_id]
        cfg = {"enabled": True, "payloads": [], "notes": ""}
        meta = self.flat.get(vrt_id)
        if self.dir and meta and meta.get("file"):
            try:
                doc = json.loads((self.dir / meta["file"]).read_text())
                cfg["enabled"] = bool(doc.get("enabled", True))
                cfg["payloads"] = list(doc.get("payloads") or [])
                cfg["notes"] = doc.get("notes", "")
            except (OSError, json.JSONDecodeError):
                pass
        self._cfg_cache[vrt_id] = cfg
        return cfg


# --------------------------------------------------------------------------- #
# Reporter
# --------------------------------------------------------------------------- #
def report(findings: list[Finding], requests_made: int, pages: int,
           json_out: str | None = None) -> None:
    print("\n" + "=" * 70)
    print(f"SCAN COMPLETE — {pages} pages crawled, {requests_made} requests sent")
    print("=" * 70)
    if not findings:
        print("No findings from the automated modules.")
    else:
        findings.sort(key=lambda f: f.priority)
        for f in findings:
            print(f"\n[{PRIORITY_LABELS.get(f.priority, '?')}] {f.title}")
            print(f"    VRT   : {f.vrt_id}")
            print(f"    URL   : {f.url}")
            if f.param:
                print(f"    Param : {f.param}")
            print(f"    Proof : {f.evidence}")
            if f.detail:
                print(f"    Note  : {f.detail}")
    if json_out:
        Path(json_out).write_text(json.dumps(
            [f.to_dict() for f in findings], indent=2, ensure_ascii=False))
        print(f"\nJSON report written to {json_out}")
    print()
