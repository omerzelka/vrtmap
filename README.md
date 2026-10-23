# VRT Scanner

A web vulnerability scanner organized around the **Bugcrowd Vulnerability
Rating Taxonomy (VRT)**. The VRT (`vrt_scanner/vrt.json`) is the single source
of truth: every check module maps to a VRT leaf id and inherits its name and
severity (P1–P5) from the catalog.

## ⚠️ Authorization

Run this **only** against systems you own or have written permission to test —
your own app, a local lab, or an in-scope bug-bounty / CTF target. The scanner
enforces a host **scope** and refuses to start without `--authorized`. Sending
these payloads at systems you don't control is unlawful.

## Install

```bash
cd ~/Desktop/vrt-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
# Spin up a legal practice target first, e.g. OWASP Juice Shop:
#   docker run --rm -p 3000:3000 bkimminich/juice-shop
python -m vrt_scanner.cli http://localhost:3000 --authorized

# Options
python -m vrt_scanner.cli http://localhost:3000 --authorized \
    --scope localhost \
    --max-pages 80 --rate 5 --concurrency 5 \
    --json report.json
```

## What it covers

Automatable VRT classes, implemented as working modules:

| VRT id | Check |
|---|---|
| `server_side_injection.sql_injection` | Error-based SQLi |
| `server_side_injection.file_inclusion.local` | Path traversal / LFI |
| `cross_site_scripting_xss.reflected` | Reflected XSS |
| `unvalidated_redirects_and_forwards.open_redirect` | Open redirect |
| `server_security_misconfiguration.missing_security_headers` | CSP/HSTS/… |
| `server_security_misconfiguration.clickjacking` | Frame protection |
| `server_security_misconfiguration.missing_secure_or_httponly_cookie_flag` | Cookie flags |
| `server_security_misconfiguration.misconfigured_cors` | CORS reflection |
| `server_security_misconfiguration.exposed_sensitive_files` | `.git`, `.env`, … |

**Not automatable** (IDOR, business logic, access control, auth bypass) are
kept as explicit `MANUAL` stub modules so the taxonomy coverage stays honest —
they need app context and human verification.

## Extend it

Add a module in `vrt_scanner/modules.py`: subclass `Module`, set `VRT_ID`,
implement `run()`, append to `ALL_MODULES`. For full taxonomy coverage, drop
the official `vrt.json` from the Bugcrowd repo over the bundled minimal one.
