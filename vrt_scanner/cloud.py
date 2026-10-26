"""Cloud engine (AWS) — EXPERIMENTAL / not validated here. Authorized only.

A separate entry point:

    python -m vrt_scanner.cloud --profile myprofile --region eu-west-1 --authorized

It uses boto3 with credentials from your environment/profile and runs
READ-ONLY checks (list/get/describe) that map to the official VRT
`cloud_security.*` leaves. It never changes anything in the account.

Needs boto3 (`pip install boto3`) and credentials for an account you own or
have written permission to assess. NOT tested here (no AWS account) — validate
against your own account before trusting the output.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core import Finding, VRTCatalog, report, report_html

CATALOG_DIR = Path(__file__).resolve().parent.parent / "vrt_catalog"

MGMT_PORTS = {22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 5900}


def _f(vrt_id, where, evidence, detail=""):
    return Finding(vrt_id=vrt_id, title="", url=where, evidence=evidence, detail=detail)


class CloudScanner:
    def __init__(self, profile=None, region=None):
        self.profile = profile
        self.region = region
        self.session = None

    def connect(self):
        import boto3
        self.session = boto3.Session(profile_name=self.profile,
                                     region_name=self.region)
        # fail fast if credentials are missing/invalid
        self.session.client("sts").get_caller_identity()

    # --- checks ------------------------------------------------------------ #
    def check_public_buckets(self):
        from botocore.exceptions import ClientError
        s3 = self.session.client("s3")
        out = []
        for b in s3.list_buckets().get("Buckets", []):
            name = b["Name"]
            public = False
            try:
                pab = s3.get_public_access_block(Bucket=name)
                cfg = pab["PublicAccessBlockConfiguration"]
                if not all(cfg.values()):
                    public = True       # not every public-access block is on
            except ClientError:
                public = True           # no public-access block configured at all
            try:
                st = s3.get_bucket_policy_status(Bucket=name)
                public = public or st["PolicyStatus"]["IsPublic"]
            except ClientError:
                pass
            if public:
                out.append(_f("cloud_security.storage_misconfigurations"
                              ".publicly_accessible_cloud_storage",
                              f"s3://{name}",
                              "bucket may be publicly accessible (public-access "
                              "block incomplete or bucket policy is public)",
                              detail="enable S3 Block Public Access on the bucket"))
        return out

    def check_unencrypted_buckets(self):
        from botocore.exceptions import ClientError
        s3 = self.session.client("s3")
        out = []
        for b in s3.list_buckets().get("Buckets", []):
            try:
                s3.get_bucket_encryption(Bucket=b["Name"])
            except ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    out.append(_f("cloud_security.storage_misconfigurations"
                                  ".unencrypted_sensitive_data_at_rest",
                                  f"s3://{b['Name']}",
                                  "bucket has no default server-side encryption"))
        return out

    def check_open_mgmt_ports(self):
        ec2 = self.session.client("ec2")
        out = []
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                fp, tp = perm.get("FromPort"), perm.get("ToPort")
                open_v4 = any(r.get("CidrIp") == "0.0.0.0/0"
                              for r in perm.get("IpRanges", []))
                open_v6 = any(r.get("CidrIpv6") == "::/0"
                              for r in perm.get("Ipv6Ranges", []))
                if not (open_v4 or open_v6) or fp is None:
                    continue
                hit = [p for p in MGMT_PORTS if fp <= p <= tp] or (fp == 0 and tp == 65535)
                if hit:
                    out.append(_f("cloud_security.network_configuration_issues"
                                  ".open_management_ports_to_the_internet",
                                  f"sg://{sg['GroupId']}",
                                  f"security group opens port(s) {hit if hit is not True else 'ALL'} "
                                  f"to the internet",
                                  detail="restrict the source CIDR to known ranges"))
        return out

    def check_logging(self):
        from botocore.exceptions import ClientError
        ct = self.session.client("cloudtrail")
        active = False
        for t in ct.describe_trails().get("trailList", []):
            try:
                if ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging"):
                    active = True
            except ClientError:
                pass
        if not active:
            return [_f("cloud_security.logging_and_monitoring_issues"
                       ".disabled_or_insufficient_logging",
                       "cloudtrail://account",
                       "no active CloudTrail trail is logging in this account/region")]
        return []

    def check_iam_admin(self):
        iam = self.session.client("iam")
        out = []
        for u in iam.list_users().get("Users", []):
            pols = iam.list_attached_user_policies(UserName=u["UserName"])
            for pol in pols.get("AttachedPolicies", []):
                if pol["PolicyName"] == "AdministratorAccess":
                    out.append(_f("cloud_security"
                                  ".identity_and_access_management_iam_misconfigurations"
                                  ".overly_permissive_iam_roles",
                                  f"iam://user/{u['UserName']}",
                                  "IAM user has AdministratorAccess attached directly",
                                  detail="prefer scoped roles over blanket admin"))
        return out

    CHECKS = ["check_public_buckets", "check_unencrypted_buckets",
              "check_open_mgmt_ports", "check_logging", "check_iam_admin"]

    def run(self):
        findings = []
        for name in self.CHECKS:
            try:
                fs = getattr(self, name)()
            except Exception as ex:
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
        prog="vrt-scanner-cloud",
        description="VRT cloud engine — AWS, read-only (authorized only).")
    p.add_argument("--profile", default=None, help="AWS profile name.")
    p.add_argument("--region", default=None, help="AWS region.")
    p.add_argument("--authorized", action="store_true",
                   help="REQUIRED: you own or may assess this account.")
    p.add_argument("--json", dest="json_out", default=None)
    p.add_argument("--html", dest="html_out", default=None)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.authorized:
        print("Refusing to scan without --authorized.\n"
              "Only run this against an account you own or may assess.",
              file=sys.stderr)
        return 1
    try:
        import boto3  # noqa: F401
    except ImportError:
        print("The cloud engine needs boto3:  pip install boto3", file=sys.stderr)
        return 2

    print("=" * 70)
    print(" VRT Scanner — Cloud engine (AWS, read-only, authorized only)")
    print("=" * 70)
    scanner = CloudScanner(profile=args.profile, region=args.region)
    try:
        scanner.connect()
    except Exception as ex:
        print(f"AWS session/credentials failed: {ex}", file=sys.stderr)
        return 3
    print("[*] Running cloud checks...")

    catalog = VRTCatalog.load_dir(CATALOG_DIR)
    findings = [_enrich(catalog, f) for f in scanner.run()]
    report(findings, 0, 0, args.json_out)
    if args.html_out:
        report_html(findings, 0, 0, "aws://account", args.html_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
