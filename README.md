# VRT Scanner

A web vulnerability scanner organized around the **Bugcrowd Vulnerability
Rating Taxonomy (VRT)**. The full official VRT (437 leaf types, release
2026-07-08) lives under `vrt_catalog/` as **one editable file per type**, and
every scanner module maps to real VRT leaf ids — so each finding carries its
exact VRT id and inherits that leaf's P1–P5 severity from the catalog.

## ⚠️ Authorization

Run this **only** against systems you own or have written permission to test —
your own app, a local lab, or an in-scope bug-bounty / CTF target. The scanner
enforces a host **scope** and refuses to start without `--authorized`.

## Install

```bash
cd ~/Desktop/vrt-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Scan

```bash
# Spin up a legal practice target first, e.g. OWASP Juice Shop:
#   docker run --rm -p 3000:3000 bkimminich/juice-shop
python -m vrt_scanner.cli http://localhost:3000 --authorized

python -m vrt_scanner.cli http://localhost:3000 --authorized \
    --scope localhost --max-pages 80 --rate 5 --json report.json

# shareable HTML report (payloads are escaped — the report is not XSS-able):
python -m vrt_scanner.cli http://localhost:3000 --authorized --html report.html
```

## Active Directory engine

A separate, credentialed engine for an AD domain (read-only LDAP; authorized
targets only). Needs `ldap3` (`pip install ldap3`).

```bash
python -m vrt_scanner.ad --dc dc01.lab.local --domain LAB \
    --user analyst --password '***' --authorized --html ad-report.html
```

Checks (all map to `active_directory.*` VRT leaves): Kerberoastable accounts,
AS-REP roastable accounts, unconstrained delegation, excessive Domain Admins,
passwords in object descriptions, weak domain password policy, dormant enabled
accounts, anonymous LDAP bind. Deep DACL/ACE abuse is not implemented yet.

## Coverage — how much of the VRT is automated

```bash
python -m vrt_scanner.coverage                 # summary by priority
python -m vrt_scanner.coverage --list auto     # which leaves are automated
python -m vrt_scanner.coverage --list none     # which still have no module
```

Current state: **12 of 437** leaf types automated, **5** marked manual
(IDOR — needs app context), the rest unmodelled. That gap is expected and
honest: most of the VRT (business logic, access control, mobile, hardware,
crypto) can't be found by a generic scanner.

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
  "enabled": true,          // set false to skip this check
  "payloads": ["' OR 1=1--"], // extra payloads injected on top of defaults
  "notes": ""
}
```

Set `enabled: false` to disable a leaf; add strings to `payloads` and the
module covering that leaf will try them too (SQLi, XSS, path traversal, open
redirect support custom payloads).

## Checks → VRT leaf ids

| Module | VRT leaf |
|---|---|
| SQL injection (error-based) | `server_side_injection.sql_injection` |
| Path traversal / LFI | `server_side_injection.file_inclusion.local` |
| Reflected XSS | `cross_site_scripting_xss.reflected.non_self` |
| Open redirect | `unvalidated_redirects_and_forwards.open_redirect.get_based` |
| CORS misconfig | `server_security_misconfiguration.unsafe_cross_origin_resource_sharing` |
| Security headers (×3) | `server_security_misconfiguration.lack_of_security_headers.*` |
| Clickjacking | `server_security_misconfiguration.clickjacking.non_sensitive_action` |
| Cookie flags (×2) | `server_security_misconfiguration.missing_secure_or_httponly_cookie_flag.*` |
| Sensitive files | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` |
| IDOR *(manual)* | `broken_access_control.idor.*` |

## Extend it

Add a module in `vrt_scanner/modules.py`: subclass `Module`, set `VRT_IDS` to
the official leaf id(s) it covers (check against `vrt_catalog/index.json`),
implement `run()` returning `Finding`s via `self.f(vrt_id, url, evidence, ...)`,
and append to `ALL_MODULES`. Run `python -m vrt_scanner.coverage` to see the
coverage number move.
