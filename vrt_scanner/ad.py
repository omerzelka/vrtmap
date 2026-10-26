"""Active Directory engine — authorized testing only.

A separate entry point from the web scanner:

    python -m vrt_scanner.ad --dc dc01.lab.local --domain LAB \\
        --user analyst --password '***' --authorized

It binds to LDAP with the credentials you provide and runs query-based checks
that map to the official Bugcrowd VRT `active_directory.*` leaves. It reads
only — it never writes to the directory. Run it only against a domain you own
or have written permission to test.

NOTE: deep DACL/ACE abuse (parsing nTSecurityDescriptor to find dangerous
rights such as WriteDacl/GenericAll) is NOT implemented here yet — it needs
security-descriptor parsing and is best validated against a real lab. The
checks below are the reliable, query-based ones.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .core import Finding, VRTCatalog, report, report_html

CATALOG_DIR = Path(__file__).resolve().parent.parent / "vrt_catalog"

# userAccountControl bit flags we test for
UAC_DISABLED = 0x0002
UAC_DONT_REQ_PREAUTH = 0x400000    # AS-REP roastable
UAC_TRUSTED_FOR_DELEGATION = 0x80000   # unconstrained delegation

DORMANT_DAYS = 90
WEAK_MIN_PWD_LEN = 14
MAX_DOMAIN_ADMINS = 5


def _f(vrt_id, where, evidence, detail=""):
    return Finding(vrt_id=vrt_id, title="", url=where, evidence=evidence, detail=detail)


class ADScanner:
    def __init__(self, dc, domain, user, password, base_dn=None,
                 use_ssl=False, port=None):
        self.dc = dc
        self.domain = domain
        self.user = user
        self.password = password
        self.base_dn = base_dn
        self.use_ssl = use_ssl
        self.port = port
        self.conn = None
        self.server = None

    def connect(self):
        from ldap3 import Server, Connection, ALL, NTLM
        self.server = Server(self.dc, get_info=ALL, use_ssl=self.use_ssl,
                             port=self.port)
        self.conn = Connection(self.server, user=f"{self.domain}\\{self.user}",
                               password=self.password, authentication=NTLM,
                               auto_bind=True)
        if not self.base_dn:
            # derive the search base from the DC's advertised naming context
            ctx = self.server.info.other.get("defaultNamingContext") \
                if self.server.info else None
            if ctx:
                self.base_dn = ctx[0] if isinstance(ctx, list) else str(ctx)
            else:
                self.base_dn = ",".join(f"DC={p}" for p in self.dc.split(".")[1:])

    def _search(self, filt, attrs):
        from ldap3 import SUBTREE
        self.conn.search(self.base_dn, filt, SUBTREE, attributes=attrs)
        return list(self.conn.entries)

    # --- individual checks ------------------------------------------------- #
    def check_kerberoastable(self):
        entries = self._search(
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
            ["sAMAccountName", "servicePrincipalName", "userAccountControl"])
        names = [str(e.sAMAccountName) for e in entries
                 if not (int(e.userAccountControl.value or 0) & UAC_DISABLED)]
        if names:
            return [_f("active_directory.kerberos_abuse.insecure_service_account_management",
                       f"ldap://{self.dc}",
                       f"{len(names)} enabled account(s) with an SPN are "
                       f"Kerberoastable: {names[:10]}",
                       detail="use strong (25+ char) managed service-account passwords")]
        return []

    def check_asrep_roastable(self):
        entries = self._search(
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            ["sAMAccountName"])
        names = [str(e.sAMAccountName) for e in entries]
        if names:
            return [_f("active_directory.kerberos_abuse.no_pre_authentication",
                       f"ldap://{self.dc}",
                       f"{len(names)} account(s) have Kerberos pre-auth disabled "
                       f"(AS-REP roastable): {names[:10]}")]
        return []

    def check_unconstrained_delegation(self):
        entries = self._search(
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
            ["sAMAccountName"])
        names = [str(e.sAMAccountName) for e in entries]
        # krbtgt and DCs legitimately have this; still worth surfacing non-DCs
        names = [n for n in names if n.lower() != "krbtgt"]
        if names:
            return [_f("active_directory.kerberos_abuse.domain_compromise_unconstrained_delegated",
                       f"ldap://{self.dc}",
                       f"account(s) trusted for unconstrained delegation: {names[:10]}",
                       detail="review each; a compromise can lead to full domain takeover")]
        return []

    def check_domain_admins(self):
        entries = self._search("(sAMAccountName=Domain Admins)", ["member"])
        if not entries:
            return []
        members = entries[0].member.values if "member" in entries[0] else []
        if len(members) > MAX_DOMAIN_ADMINS:
            return [_f("active_directory.configuration_weaknesses.excessive_domain_admin_membership",
                       f"ldap://{self.dc}",
                       f"Domain Admins has {len(members)} members "
                       f"(> {MAX_DOMAIN_ADMINS})",
                       detail="keep privileged group membership minimal")]
        return []

    def check_passwords_in_description(self):
        entries = self._search(
            "(&(objectCategory=person)(objectClass=user)(description=*))",
            ["sAMAccountName", "description"])
        import re
        pat = re.compile(r"pass|pwd|parol|credential|sifre", re.I)
        hits = [str(e.sAMAccountName) for e in entries
                if pat.search(str(e.description))]
        if hits:
            return [_f("active_directory.configuration_weaknesses.passwords_found_domain_description",
                       f"ldap://{self.dc}",
                       f"account description field mentions a password on: {hits[:10]}")]
        return []

    def check_password_policy(self):
        self.conn.search(self.base_dn, "(objectClass=domainDNS)",
                         attributes=["minPwdLength"])
        if not self.conn.entries:
            return []
        try:
            mn = int(self.conn.entries[0].minPwdLength.value)
        except (ValueError, TypeError):
            return []
        if mn < WEAK_MIN_PWD_LEN:
            return [_f("active_directory.configuration_weaknesses.weak_domain_password_policy",
                       f"ldap://{self.dc}",
                       f"domain minimum password length is {mn} "
                       f"(< {WEAK_MIN_PWD_LEN})")]
        return []

    def check_dormant_accounts(self):
        entries = self._search(
            "(&(objectCategory=person)(objectClass=user)(lastLogonTimestamp=*))",
            ["sAMAccountName", "lastLogonTimestamp", "userAccountControl"])
        cutoff = datetime.now(timezone.utc) - timedelta(days=DORMANT_DAYS)
        dormant = []
        for e in entries:
            if int(e.userAccountControl.value or 0) & UAC_DISABLED:
                continue
            last = self._as_datetime(e.lastLogonTimestamp.value)
            if last is not None and last < cutoff:
                dormant.append(str(e.sAMAccountName))
        if dormant:
            return [_f("active_directory.configuration_weaknesses.dormant_enabled_user_accounts",
                       f"ldap://{self.dc}",
                       f"{len(dormant)} enabled account(s) idle > {DORMANT_DAYS} "
                       f"days: {dormant[:10]}",
                       detail="disable accounts that are no longer in use")]
        return []

    @staticmethod
    def _as_datetime(val):
        """lastLogonTimestamp may arrive as a datetime (ldap3 formatter) or a
        raw Windows FILETIME integer; normalise to an aware datetime."""
        if isinstance(val, datetime):
            return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
        try:
            ft = int(val)
        except (ValueError, TypeError):
            return None
        if ft <= 0:
            return None
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft / 10)

    def check_anonymous_bind(self):
        """A second, credential-less connection: if the DC lets an anonymous
        client read directory objects, that is a disclosure issue."""
        from ldap3 import Server, Connection, ALL, ANONYMOUS
        try:
            s = Server(self.dc, get_info=ALL, use_ssl=self.use_ssl, port=self.port)
            c = Connection(s, authentication=ANONYMOUS, auto_bind=True)
            c.search(self.base_dn, "(objectClass=user)", attributes=["sAMAccountName"])
            ok = bool(c.entries)
            c.unbind()
        except Exception:
            return []
        if ok:
            return [_f("active_directory.sensitive_data_exposure.ldap_anonymous_bind_enabled",
                       f"ldap://{self.dc}",
                       "anonymous LDAP bind can read directory objects")]
        return []

    CHECKS = [
        "check_anonymous_bind",
        "check_kerberoastable",
        "check_asrep_roastable",
        "check_unconstrained_delegation",
        "check_domain_admins",
        "check_passwords_in_description",
        "check_password_policy",
        "check_dormant_accounts",
    ]

    def run(self):
        findings = []
        for name in self.CHECKS:
            try:
                fs = getattr(self, name)()
            except Exception as ex:               # one bad check must not kill the scan
                print(f"    ! {name}: {ex}")
                continue
            if fs:
                print(f"    + {name}: {len(fs)} finding(s)")
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
        prog="vrt-scanner-ad",
        description="VRT Active Directory engine (authorized targets only).")
    p.add_argument("--dc", required=True, help="Domain controller host/IP.")
    p.add_argument("--domain", required=True, help="NetBIOS or DNS domain name.")
    p.add_argument("--user", required=True, help="Username for the LDAP bind.")
    p.add_argument("--password", required=True, help="Password for the bind.")
    p.add_argument("--base-dn", default=None,
                   help="Search base (default: auto from the DC).")
    p.add_argument("--ssl", action="store_true", help="Use LDAPS (port 636).")
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--authorized", action="store_true",
                   help="REQUIRED: you confirm you own or may test this domain.")
    p.add_argument("--json", dest="json_out", default=None)
    p.add_argument("--html", dest="html_out", default=None)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.authorized:
        print("Refusing to scan without --authorized.\n"
              "Only run this against a domain you own or have written "
              "permission to test.", file=sys.stderr)
        return 1
    try:
        import ldap3  # noqa: F401
    except ImportError:
        print("The AD engine needs ldap3:  pip install ldap3", file=sys.stderr)
        return 2

    print("=" * 70)
    print(" VRT Scanner — Active Directory engine (authorized testing only)")
    print(f" Target DC: {args.dc}  domain: {args.domain}")
    print("=" * 70)

    scanner = ADScanner(args.dc, args.domain, args.user, args.password,
                        base_dn=args.base_dn, use_ssl=args.ssl, port=args.port)
    try:
        scanner.connect()
    except Exception as ex:
        print(f"LDAP bind failed: {ex}", file=sys.stderr)
        return 3
    print(f"[*] Bound as {args.domain}\\{args.user}; base DN: {scanner.base_dn}")
    print("[*] Running AD checks...")

    catalog = VRTCatalog.load_dir(CATALOG_DIR)
    findings = [_enrich(catalog, f) for f in scanner.run()]
    report(findings, 0, 0, args.json_out)
    if args.html_out:
        report_html(findings, 0, 0, f"ldap://{args.dc}", args.html_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
