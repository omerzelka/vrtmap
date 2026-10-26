"""Coverage report: cross-reference the scanner's modules against the full
437-type VRT catalog and show what is automated, what is manual, and what has
no module yet — broken down by priority.

Run with:  python -m vrt_scanner.coverage
Options:   --list auto|manual|none   (print the leaf ids in that bucket)
           --missing-ids             (warn about module ids absent from catalog)
"""
from __future__ import annotations

import argparse
from pathlib import Path

from .core import VRTCatalog, PRIORITY_LABELS
from .modules import ALL_MODULES

CATALOG_DIR = Path(__file__).resolve().parent.parent / "vrt_catalog"


def build() -> tuple[VRTCatalog, dict[str, str], list[str]]:
    catalog = VRTCatalog.load_dir(CATALOG_DIR)
    status: dict[str, str] = {}          # vrt_id -> auto | none
    unknown: list[str] = []              # module ids not present in catalog
    auto_ids = set()
    for mod in ALL_MODULES:
        for vid in mod.VRT_IDS:
            if catalog.info(vid) is None:
                unknown.append(f"{type(mod).__name__}: {vid}")
            else:
                auto_ids.add(vid)
    for vid in catalog.flat:
        status[vid] = "auto" if vid in auto_ids else "none"
    return catalog, status, unknown


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vrt-coverage")
    ap.add_argument("--list", choices=["auto", "none"])
    ap.add_argument("--missing-ids", action="store_true")
    args = ap.parse_args(argv)

    catalog, status, unknown = build()
    total = len(status)
    counts = {s: sum(1 for v in status.values() if v == s)
              for s in ("auto", "none")}

    print("=" * 66)
    print(f" VRT COVERAGE — {total} leaf types total")
    print("=" * 66)
    print(f" automated (active module) : {counts['auto']:>3}  "
          f"({counts['auto']*100//total}%)")
    print(f" no module                 : {counts['none']:>3}")

    print("\n By priority (automated / total):")
    for p in (1, 2, 3, 4, 5, None):
        leaves = [v for v, m in catalog.flat.items() if m["priority"] == p]
        if not leaves:
            continue
        auto = sum(1 for v in leaves if status[v] == "auto")
        label = PRIORITY_LABELS.get(p, "Varies") if p else "Varies"
        bar = "#" * (auto * 20 // max(len(leaves), 1))
        print(f"   {label:<12} {auto:>3}/{len(leaves):<3} {bar}")

    if args.list:
        print(f"\n Leaves in bucket '{args.list}':")
        for v in sorted(v for v, m in status.items() if m == args.list):
            print(f"   - {v}")

    if unknown:
        print(f"\n ⚠ {len(unknown)} module id(s) not found in catalog:")
        if args.missing_ids:
            for u in unknown:
                print(f"   - {u}")
        else:
            print("   (run with --missing-ids to list them)")

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
