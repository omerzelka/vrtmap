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
    Scope, HttpEngine, Crawler, VRTCatalog, report, OutOfScope,
)
from .modules import ALL_MODULES

VRT_PATH = Path(__file__).with_name("vrt.json")


async def orchestrate(engine: HttpEngine, catalog: VRTCatalog,
                      start_url: str, max_pages: int):
    print(f"[*] Crawling {start_url} (max {max_pages} pages)...")
    pages = await Crawler(engine, max_pages=max_pages).crawl(start_url)
    print(f"[*] Discovered {len(pages)} page(s). Running "
          f"{len(ALL_MODULES)} VRT modules...")
    findings = []
    for mod in ALL_MODULES:
        info = catalog.info(mod.VRT_ID)
        if info:                      # sync module metadata with VRT catalog
            mod.NAME = mod.NAME if "MANUAL" in mod.NAME else info["name"]
            mod.DEFAULT_PRIORITY = info["priority"]
        try:
            fs = await mod.run(engine, pages)
        except OutOfScope as e:
            print(f"    ! {mod.VRT_ID}: skipped out-of-scope target {e}")
            continue
        except Exception as e:        # one bad module must not kill the scan
            print(f"    ! {mod.VRT_ID}: module error: {e}")
            continue
        for f in fs:
            if info:
                f.priority = info["priority"]
        if fs:
            print(f"    + {mod.VRT_ID}: {len(fs)} finding(s)")
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
    return p


async def _amain(args) -> int:
    host = urlparse(args.target).hostname
    if not host:
        print("Invalid target URL.", file=sys.stderr)
        return 2
    scope = Scope(args.scope if args.scope else [host])
    catalog = VRTCatalog.load(VRT_PATH)
    engine = HttpEngine(scope, rate=args.rate, concurrency=args.concurrency,
                        timeout=args.timeout, verify_tls=not args.insecure)
    try:
        pages, findings = await orchestrate(
            engine, catalog, args.target, args.max_pages)
    finally:
        await engine.aclose()
    report(findings, engine.requests_made, len(pages), args.json_out)
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
