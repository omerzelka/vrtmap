# VRT Scanner

A web vulnerability scanner organized around the **Bugcrowd Vulnerability
Rating Taxonomy (VRT)**. The full official VRT (437 leaf types, release
2026-07-08) lives under `vrt_catalog/` as **one editable file per type**, and
every scanner module maps to real VRT leaf ids — so each finding carries its
exact VRT id and inherits that leaf's P1–P5 severity from the catalog.

It crawls a target (following links and seeding from `robots.txt` / `sitemap.xml`),
tests URL parameters **and form fields**, and runs 30+ checks: injection
(SQLi, LFI, reflected/Referer XSS), redirects, CORS, security headers,
clickjacking, cookie flags, sensitive-file and directory-listing exposure,
TLS posture, DNS hygiene, SPF/DMARC spoofing, exposed admin portals, and more.

## ⚠️ Authorization

Run this **only** against systems you own or have written permission to test —
your own app, a local lab, or an in-scope bug-bounty / CTF target. The scanner
enforces a host **scope** and refuses to start without `--authorized`.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt            # core

# optional: enables the SPF/DMARC and DNS-hygiene checks (skipped if absent)
pip install -r requirements-extra.txt
```

Or install the package, which gives a `vrt` command:

```bash
pip install -e .            # + the `vrt` command
pip install -e '.[dns]'     # also the DNS/mail checks ([dev] for tests)
```

`python -m vrt_scanner <url> ...` always works even without `vrt` on your PATH.

## Scan

```bash
# Spin up a legal practice target first, e.g. OWASP Juice Shop:
#   docker run --rm -p 3000:3000 bkimminich/juice-shop
python -m vrt_scanner http://localhost:3000 --authorized

python -m vrt_scanner http://localhost:3000 --authorized \
    --scope localhost --max-pages 80 --rate 5 --json report.json

# shareable HTML report (payloads are escaped — the report is not XSS-able):
python -m vrt_scanner http://localhost:3000 --authorized --html report.html
```

## Coverage — how much of the VRT is automated

```bash
python -m vrt_scanner.coverage              # summary by priority
python -m vrt_scanner.coverage --list auto  # which leaves are automated
python -m vrt_scanner.coverage --list none  # which have no module
```

**47 of 437** leaf types are automated. That gap is expected and honest: most
of the VRT (business logic, auth/session flows, access control, mobile,
hardware, crypto) cannot be found by a generic automated scanner and requires
manual testing — so the tool does not pretend to cover them.

## The catalog — `vrt_catalog/`

The taxonomy is mirrored as a directory tree, one JSON file per leaf type:

```
vrt_catalog/
├── server_side_injection/sql_injection.json
├── cross_site_scripting_xss/reflected/non_self.json
├── ... (437 files, 37 top categories)
├── _source/vulnerability-rating-taxonomy.json   # original official JSON
├── index.json                                   # machine-readable list
└── INDEX.md                                      # grouped by P1–P5
```

Each file has editable hooks the scanner reads at runtime:

```json
{
  "vrt_id": "server_side_injection.sql_injection",
  "priority": 1,
  "enabled": true,            // set false to skip this check
  "payloads": ["' OR 1=1--"], // extra payloads injected on top of defaults
  "notes": ""
}
```

Set `enabled: false` to disable a leaf; add strings to `payloads` and the
module covering that leaf will try them too (SQLi, XSS, path traversal and open
redirect support custom payloads).

## A few of the checks

| Module | VRT leaf |
|---|---|
| SQL injection (error-based, params + forms) | `server_side_injection.sql_injection` |
| Reflected XSS (params + forms) | `cross_site_scripting_xss.reflected.non_self` |
| Path traversal / LFI | `server_side_injection.file_inclusion.local` |
| Open redirect | `unvalidated_redirects_and_forwards.open_redirect.get_based` |
| CORS misconfig | `server_security_misconfiguration.unsafe_cross_origin_resource_sharing` |
| Security headers | `server_security_misconfiguration.lack_of_security_headers.*` |
| TLS posture (cert / protocol / cipher) | `server_security_misconfiguration.insecure_ssl.*` |
| DNS hygiene (CAA / DNSSEC / AXFR) | `server_security_misconfiguration.misconfigured_dns.*` |
| Email spoofing (SPF / DMARC) | `server_security_misconfiguration.mail_server_misconfiguration.*` |
| Sensitive files / directory listing | `sensitive_data_exposure.disclosure_of_secrets.*` |

Run `python -m vrt_scanner.coverage --list auto` for the full list.

## Extend it

Add a module in `vrt_scanner/modules.py`: subclass `Module`, set `VRT_IDS` to
the official leaf id(s) it covers (check against `vrt_catalog/index.json`),
implement `run()` returning `Finding`s via `self.f(vrt_id, url, evidence, ...)`,
and append to `ALL_MODULES`. Run `python -m vrt_scanner.coverage` to see the
coverage number move.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

Unit tests cover the core helpers and the detection modules; an integration
test runs a full scan against an embedded intentionally-vulnerable server and
asserts the form-based XSS and SQLi are found. No network needed. CI runs the
suite on Python 3.9 / 3.11 / 3.12.

## License

MIT — see [LICENSE](LICENSE).
