# Engines — multi-domain roadmap

The VRT (437 leaf types, 37 top categories) is **not** a web-only taxonomy. No
single tool can scan "everything": each domain needs a different input, access
level and protocol. So the scanner is a **framework** — a shared VRT catalog,
`Finding` model, `--authorized`/scope gate and unified report — with a set of
**engines** plugged in behind one entry point.

```
vrt web    https://site --authorized
vrt ad     --dc 10.0.0.1 --user u --authorized
vrt cloud  --profile prod --authorized
vrt mobile app.apk --authorized
```

Every engine maps its findings back to the **same official VRT leaf ids** and
the same report format. The value of this tool is not "scans all of VRT" — it
is **translating many domain-specific checks into one VRT language**.

> Realistic ceiling: of 437 leaves, roughly **~150** can be automated by *any*
> tool. The rest require credentials, a binary/file, or are purely manual
> (business logic, AI, bias, privacy). That gap is expected and honest.

---

## 1. Web — *implemented*

- **Input:** start URL
- **Library:** `httpx` + `beautifulsoup4` (already in `requirements.txt`)
- **Code:** `vrt_scanner/` (core engine, crawler, modules)
- **Status:** 12 leaves automated, 5 manual. This is the strong, mature engine.

| Category | Leaves | Automation |
|---|---|---|
| server_security_misconfiguration | 84 | partial (headers / CORS / clickjacking auto; most manual) |
| server_side_injection | 22 | good (SQLi, LFI, SSRF) |
| broken_authentication_and_session_management | 21 | partial |
| cross_site_scripting_xss | 14 | good |
| broken_access_control | 10 | weak (IDOR is manual) |
| cross_site_request_forgery_csrf | 6 | partial |
| unvalidated_redirects_and_forwards | 6 | good |
| application_level_denial_of_service_dos | 5 | ⚠️ do **not** auto-test (causes harm) |
| client_side_injection | 3 | partial |
| insecure_data_transport | 3 | good (TLS inspection) |
| using_components_with_known_vulnerabilities | 4 | good (version → CVE lookup) |

**Next for this engine:** directory listing, verbose error / stack-trace
disclosure, missing HTTPS enforcement / mixed content — all clone the existing
`SensitiveFiles` / `SecurityHeaders` pattern.

---

## 2. Network / infrastructure — *planned*

- **Input:** host / IP
- **Library:** stdlib `socket`, `ssl`; optionally a port-scan helper
- **Note:** partly outside the `httpx` model — needs raw sockets / TLS probing.

| Category | Leaves |
|---|---|
| sensitive_data_exposure | 34 (some overlap with Web) |
| insufficient_security_configurability | 20 |
| protocol_specific_misconfiguration | 4 |
| external_behavior | 9 |
| network_security_misconfiguration | 1 |

---

## 3. Active Directory — *query-based checks implemented*

- **Input:** domain, DC address, **valid credentials** (authenticated bind)
- **Library:** `ldap3`
- **Code / entry point:** `vrt_scanner/ad.py` — `python -m vrt_scanner.ad`
- **Status:** 8 query-based checks implemented (Kerberoastable, AS-REP
  roastable, unconstrained delegation, excessive Domain Admins, passwords in
  descriptions, weak password policy, dormant enabled accounts, anonymous
  bind). Read-only. **Must be validated against a real lab DC.**
- **Still TODO:** deep DACL/ACE abuse — parse `nTSecurityDescriptor`, flag
  dangerous rights (WriteDacl, GenericAll, WriteOwner, AddMember…) from
  low-priv principals onto high-value objects; ADCS misconfig.
- **Note:** completely independent of `HttpEngine`; its own entry point. Run
  only against your own lab or a domain you have written permission to test.

| Category | Leaves |
|---|---|
| active_directory (DACL abuse, Kerberos abuse, ADCS, SCCM, config weaknesses) | 19 |

---

## 4. Cloud — *planned*

- **Input:** cloud **API credentials** (profile / keys)
- **Library:** `boto3` (AWS), `azure-sdk`, `google-cloud` SDKs

| Category | Leaves |
|---|---|
| cloud_security | 9 |

---

## 5. Mobile — *planned*

- **Input:** `.apk` / `.ipa` **file**
- **Library:** static analysis (apktool / androguard; MobSF-style checks). The
  installed `rea` tooling overlaps here.

| Category | Leaves |
|---|---|
| mobile_security_misconfiguration | 5 |
| insecure_data_storage | 5 |

---

## 6. Binary / hardware — *mostly manual*

- **Input:** firmware image / binary
- **Library:** reverse engineering — Ghidra / `rea` MCP (already set up)
- **Note:** heavily manual; automation is limited to triage, not findings.

| Category | Leaves |
|---|---|
| automotive_security_misconfiguration | 31 |
| insecure_os_firmware | 16 |
| lack_of_binary_hardening | 4 |
| physical_security_issues | 4 |

---

## 7. Crypto / Web3 — *planned*

- **Input:** Solidity source / contract bytecode / address
- **Library:** `slither`, `mythril`, chain RPC clients

| Category | Leaves |
|---|---|
| cryptographic_weakness | 31 |
| decentralized_application_misconfiguration | 17 |
| smart_contract_misconfiguration | 14 |
| zero_knowledge_security_misconfiguration | 6 |
| blockchain_infrastructure_misconfiguration | 1 |

---

## ❌ No engine — not automatable (human / process)

These are never found by a tool. Mark them `MANUAL=True` in the catalog so
coverage stays honest.

| Category | Leaves |
|---|---|
| ai_application_security | 19 |
| algorithmic / data / societal / developer / misinterpretation biases | 8 |
| privacy_concerns | 1 |
| indicators_of_compromise | 1 |

---

## Summary

| Engine | ~Leaves | Realistic automation | Status |
|---|---|---|---|
| 1. Web | ~178 | medium-good | **implemented** |
| 2. Network | ~68 | medium | planned |
| 3. Active Directory | 19 | good (with creds) | planned |
| 4. Cloud | 9 | good (with keys) | planned |
| 5. Mobile | 10 | good (with file) | planned |
| 6. Binary / hardware | 55 | mostly manual | later |
| 7. Crypto / Web3 | 69 | medium (with source) | later |
| ❌ Manual | 29 | none — human work | catalog-only |

**Build order:** mature the Web engine first → add Active Directory as the
proof that the framework is truly multi-domain → refactor `cli.py` into
subcommands (`vrt web` / `vrt ad` / …) → add the rest over time.

> **Authorization applies to every engine.** Each one must enforce the same
> rule as Web: run only against systems you own or have written permission to
> test. Credentials, files and scope are never an exception to this.
