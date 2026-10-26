"""Entry point: python -m vrtmap <url> --authorized [options]

Equivalent to `python -m vrtmap.cli`.
"""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
