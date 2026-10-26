"""Headless (JS-rendering) crawler — EXPERIMENTAL / not validated here.

Needs Playwright:  pip install playwright  &&  playwright install chromium

SPAs (React/Angular/Vue) build their DOM with JavaScript, so the default
httpx+BeautifulSoup crawler sees almost nothing (we saw this on Juice Shop:
1 page). This crawler drives a real Chromium, waits for the page to render,
then extracts the SAME links and forms the normal crawler would — producing
identical `Page` objects, so every existing detection module works unchanged.

    python -m vrt_scanner.cli <url> --authorized --headless
"""
from __future__ import annotations

from urllib.parse import urldefrag, urljoin

from .core import Page, HttpEngine, same_origin, BeautifulSoup, Crawler


class HeadlessCrawler:
    def __init__(self, engine: HttpEngine, max_pages: int = 50,
                 timeout_ms: int = 15000):
        self.engine = engine
        self.max_pages = max_pages
        self.timeout_ms = timeout_ms

    async def crawl(self, start_url: str) -> list[Page]:
        from playwright.async_api import async_playwright
        queue = [start_url]
        seen: set[str] = set()
        pages: list[Page] = []
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            context = await browser.new_context(
                user_agent="vrt-scanner/0.1 (authorized-testing; headless)")
            try:
                while queue and len(pages) < self.max_pages:
                    url = urldefrag(queue.pop(0)).url
                    if url in seen or not self.engine.scope.allows(url):
                        continue
                    seen.add(url)
                    tab = await context.new_page()
                    try:
                        resp = await tab.goto(url, wait_until="networkidle",
                                              timeout=self.timeout_ms)
                        html = await tab.content()
                    except Exception:
                        await tab.close()
                        continue
                    status = resp.status if resp else 0
                    headers = dict(resp.headers) if resp else {}
                    await tab.close()

                    soup = BeautifulSoup(html, "html.parser")
                    forms = Crawler._parse_forms(soup, url)
                    links = []
                    for a in soup.find_all("a", href=True):
                        nxt = urldefrag(urljoin(url, a["href"])).url
                        if nxt.startswith("http") and same_origin(nxt, start_url):
                            links.append(nxt)
                            if nxt not in seen and self.engine.scope.allows(nxt):
                                queue.append(nxt)
                    pages.append(Page(url=url, status=status, headers=headers,
                                      text=html, forms=forms, links=links))
            finally:
                await browser.close()
        return pages
