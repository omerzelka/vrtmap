"""Unified entry point:

    python -m vrt_scanner web   <url> --authorized [...]
    python -m vrt_scanner ad    --dc ... --authorized [...]
    python -m vrt_scanner cloud --authorized [...]

It just dispatches to the per-engine CLIs; the individual entry points still
work unchanged (python -m vrt_scanner.cli / .ad / .cloud).
"""
import sys

USAGE = (
    "usage: python -m vrt_scanner <engine> [options]\n"
    "  engines:\n"
    "    web    crawl + scan a web target\n"
    "    ad     Active Directory (LDAP, needs credentials)\n"
    "    cloud  AWS account (read-only, needs credentials)\n"
    "  per-engine help: python -m vrt_scanner <engine> --help"
)

ENGINES = {"web": "cli", "ad": "ad", "cloud": "cloud"}


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    if not argv:
        print(USAGE, file=sys.stderr)
        return 1
    if argv[0] in ("-h", "--help"):
        print(USAGE)
        return 0
    engine, rest = argv[0], argv[1:]
    module = ENGINES.get(engine)
    if module is None:
        print(f"unknown engine '{engine}'\n\n{USAGE}", file=sys.stderr)
        return 2
    import importlib
    return importlib.import_module(f".{module}", __package__).main(rest)


if __name__ == "__main__":
    raise SystemExit(main())
