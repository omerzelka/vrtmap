"""Command-line entry point and orchestrator.

Run with:  python -m vrt_scanner.cli https://your-target --authorized
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from urllib.parse import urlparse

from .core import (
    Scope, HttpEngine, Crawler, VRTCatalog, report, report_html, OutOfScope,
)
from .modules import ALL_MODULES

CATALOG_DIR = Path(__file__).resolve().parent.parent / "vrt_catalog"


def _enrich(catalog: VRTCatalog, finding):
    """Fill a finding's title and priority from its specific VRT leaf."""
    info = catalog.info(finding.vrt_id)
    if info:
        finding.title = info["name"]
        finding.priority = info["priority"]
    elif not finding.title:
        finding.title = finding.vrt_id
    return finding


async def orchestrate(engine: HttpEngine, catalog: VRTCatalog,
                      start_url: str, max_pages: int):
    print(f"[*] Crawling {start_url} (max {max_pages} pages)...")
    pages = await Crawler(engine, max_pages=max_pages).crawl(start_url)
    active = [m for m in ALL_MODULES if not m.MANUAL]
    print(f"[*] Discovered {len(pages)} page(s). Running "
          f"{len(active)} active VRT modules...")
    findings = []
    for mod in active:
        name = type(mod).__name__
        # per-leaf config from the catalog: enabled + custom payloads
        cfgs = [(vid, catalog.leaf_config(vid)) for vid in mod.VRT_IDS
                if catalog.info(vid)]
        if cfgs and not any(c["enabled"] for _, c in cfgs):
            print(f"    - {name}: all leaves disabled in catalog, skipped")
            continue
        mod.extra_payloads = [p for _, c in cfgs for p in c["payloads"]]
        try:
            fs = await mod.run(engine, pages)
        except OutOfScope as e:
            print(f"    ! {name}: skipped out-of-scope target {e}")
            continue
        except Exception as e:        # one bad module must not kill the scan
            print(f"    ! {name}: module error: {e}")
            continue
        # drop findings whose specific leaf is disabled in the catalog
        fs = [f for f in fs if catalog.leaf_config(f.vrt_id)["enabled"]]
        fs = [_enrich(catalog, f) for f in fs]
        if fs:
            print(f"    + {name}: {len(fs)} finding(s)")
        findings.extend(fs)
    return pages, findings


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vrt-scanner",
        description="VRT-organized web vulnerability scanner "
                    "(authorized targets only).")
    p.add_argument("target", help="Start URL, e.g. https://localhost:3000")
    p.add_argument("--authorized", action="store_true",
                   help="REQUIRED: you confirm you own or have written "
                        "permission to test the target.")
    p.add_argument("--scope", nargs="*", default=None,
                   help="Allowed hosts (default: the target's host only).")
    p.add_argument("--max-pages", type=int, default=50)
    p.add_argument("--rate", type=float, default=5.0,
                   help="Max requests/second (default 5).")
    p.add_argument("--concurrency", type=int, default=5)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--insecure", action="store_true",
                   help="Do not verify TLS certificates.")
    p.add_argument("--json", dest="json_out", default=None,
                   help="Write findings to this JSON file.")
    p.add_argument("--html", dest="html_out", default=None,
                   help="Write a shareable HTML report to this file.")
    return p


async def _amain(args) -> int:
    host = urlparse(args.target).hostname
    if not host:
        print("Invalid target URL.", file=sys.stderr)
        return 2
    scope = Scope(args.scope if args.scope else [host])
    catalog = VRTCatalog.load_dir(CATALOG_DIR)
    engine = HttpEngine(scope, rate=args.rate, concurrency=args.concurrency,
                        timeout=args.timeout, verify_tls=not args.insecure)
    try:
        pages, findings = await orchestrate(
            engine, catalog, args.target, args.max_pages)
    finally:
        await engine.aclose()
    report(findings, engine.requests_made, len(pages), args.json_out)
    if args.html_out:
        report_html(findings, engine.requests_made, len(pages),
                    args.target, args.html_out)
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.authorized:
        print("Refusing to scan without --authorized.\n"
              "Only run this against systems you own or have written "
              "permission to test (your own app, a local lab, or an "
              "in-scope bug-bounty / CTF target).", file=sys.stderr)
        return 1
    print("=" * 70)
    print(" VRT Scanner — authorized testing only")
    print(f" Target: {args.target}")
    print("=" * 70)
    try:
        return asyncio.run(_amain(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
