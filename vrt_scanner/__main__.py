"""Entry point: python -m vrt_scanner <url> --authorized [options]

Equivalent to `python -m vrt_scanner.cli`.
"""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
