"""Mobile engine (Android APK) — static analysis. Authorized only.

    python -m vrt_scanner.mobile app.apk --authorized [--html r.html]

Two layers:
  * ZIP layer (always available, no extra dependency): treats the APK as the
    zip it is and scans its entries for hardcoded secrets, external-storage
    usage, and the absence of any certificate-pinning marker.
  * Manifest layer (optional, needs androguard — `pip install androguard`):
    parses AndroidManifest.xml for allowBackup and exported components. This
    layer is EXPERIMENTAL and should be validated against real APKs.

Findings map to the official VRT `mobile_security_misconfiguration.*`,
`insecure_data_storage.*` and `broken_access_control.*` leaves. The APK is only
read (as a zip / parsed) — never executed. Analyze only apps you own or may test.
"""
from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path

from .core import Finding, VRTCatalog, report, report_html

CATALOG_DIR = Path(__file__).resolve().parent.parent / "vrt_catalog"

# hardcoded-secret signatures scanned across APK entries
SECRET_PATTERNS = {
    "Google API key": re.compile(rb"AIza[0-9A-Za-z\-_]{35}"),
    "AWS access key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "private key block": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "Slack token": re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "GitHub token": re.compile(rb"ghp_[0-9A-Za-z]{36}"),
    "generic password assignment": re.compile(rb"(?i)(?:password|passwd|secret|api[_-]?key)\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']"),
}
EXTERNAL_STORAGE = re.compile(rb"getExternalStorage|WRITE_EXTERNAL_STORAGE|/sdcard/")
PINNING_MARKERS = re.compile(rb"CertificatePinner|network_security_config|<pin-set|sha256/")
MAX_ENTRY = 8 * 1024 * 1024   # don't read entries larger than 8 MiB


def _f(vrt_id, where, evidence, detail=""):
    return Finding(vrt_id=vrt_id, title="", url=where, evidence=evidence, detail=detail)


class MobileScanner:
    def __init__(self, apk_path):
        self.apk = apk_path

    # --- ZIP layer (always runs) ------------------------------------------ #
    def scan_zip(self):
        out = []
        found_secrets = {}
        uses_external = False
        has_pinning = False
        with zipfile.ZipFile(self.apk) as z:
            for name in z.namelist():
                info = z.getinfo(name)
                if info.is_dir() or info.file_size > MAX_ENTRY:
                    continue
                try:
                    data = z.read(name)
                except Exception:
                    continue
                for label, pat in SECRET_PATTERNS.items():
                    if pat.search(data):
                        found_secrets.setdefault(label, name)
                if EXTERNAL_STORAGE.search(data):
                    uses_external = True
                if PINNING_MARKERS.search(data):
                    has_pinning = True
        if found_secrets:
            where = ", ".join(f"{v} ({k})" for k, v in list(found_secrets.items())[:5])
            out.append(_f("insecure_data_storage.server_side_credentials_storage.plaintext",
                          self.apk,
                          f"hardcoded secret(s) in the APK: {where}",
                          detail="move secrets server-side; never ship them in the app"))
        if uses_external:
            out.append(_f("insecure_data_storage.sensitive_application_data_stored_unencrypted"
                          ".on_external_storage", self.apk,
                          "app references external storage (/sdcard, WRITE_EXTERNAL_STORAGE) "
                          "— confirm no sensitive data is written there unencrypted"))
        if not has_pinning:
            out.append(_f("mobile_security_misconfiguration.ssl_certificate_pinning.absent",
                          self.apk,
                          "no certificate-pinning marker found (CertificatePinner / "
                          "network_security_config pin-set)",
                          detail="heuristic — verify manually; pinning may be done differently"))
        return out

    # --- manifest layer (optional, androguard) ----------------------------- #
    def scan_manifest(self):
        try:
            try:
                from androguard.core.apk import APK          # androguard >= 4
            except ImportError:
                from androguard.core.bytecodes.apk import APK  # androguard 3.x
        except ImportError:
            print("    - manifest layer: skipped (needs androguard); see TODO-user.md")
            return []
        out = []
        try:
            apk = APK(self.apk)
        except Exception as ex:
            print(f"    ! manifest parse failed: {ex}")
            return []
        if apk.get_attribute_value("application", "allowBackup") in ("true", None):
            out.append(_f("mobile_security_misconfiguration.auto_backup_allowed_by_default",
                          self.apk,
                          "android:allowBackup is enabled (or defaulted) — app data is "
                          "backup-extractable",
                          detail="set android:allowBackup=\"false\" unless required"))
        exported = []
        for kind in ("activity", "service", "receiver", "provider"):
            for comp in apk.get_elements(kind, "exported"):
                exported.append(f"{kind}:{comp}")
        if exported:
            out.append(_f("broken_access_control.exposed_sensitive_android_intent",
                          self.apk,
                          f"exported component(s): {exported[:10]}",
                          detail="exported components are reachable by other apps — "
                                 "protect with permissions or set exported=false"))
        return out

    def run(self):
        findings = []
        for layer in (self.scan_manifest, self.scan_zip):
            try:
                fs = layer()
            except Exception as ex:
                print(f"    ! {layer.__name__}: {ex}")
                continue
            if fs:
                print(f"    + {layer.__name__}: {len(fs)} finding(s)")
            findings.extend(fs)
        return findings


def _enrich(catalog, finding):
    info = catalog.info(finding.vrt_id)
    if info:
        finding.title = info["name"]
        finding.priority = info["priority"]
    elif not finding.title:
        finding.title = finding.vrt_id
    return finding


def build_parser():
    p = argparse.ArgumentParser(
        prog="vrt-scanner-mobile",
        description="VRT mobile engine — Android APK static analysis (authorized only).")
    p.add_argument("apk", help="Path to the .apk file.")
    p.add_argument("--authorized", action="store_true",
                   help="REQUIRED: you own or may test this app.")
    p.add_argument("--json", dest="json_out", default=None)
    p.add_argument("--html", dest="html_out", default=None)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.authorized:
        print("Refusing to scan without --authorized.\n"
              "Only analyze apps you own or have written permission to test.",
              file=sys.stderr)
        return 1
    if not Path(args.apk).is_file() or not zipfile.is_zipfile(args.apk):
        print(f"Not a readable APK (zip) file: {args.apk}", file=sys.stderr)
        return 2

    print("=" * 70)
    print(" VRT Scanner — Mobile engine (Android APK, authorized only)")
    print(f" APK: {args.apk}")
    print("=" * 70)
    print("[*] Running mobile checks...")

    catalog = VRTCatalog.load_dir(CATALOG_DIR)
    findings = [_enrich(catalog, f) for f in MobileScanner(args.apk).run()]
    report(findings, 0, 0, args.json_out)
    if args.html_out:
        report_html(findings, 0, 0, f"apk://{Path(args.apk).name}", args.html_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
