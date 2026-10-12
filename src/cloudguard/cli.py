"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from . import __version__
from .engine import merge_results, run_scan
from .models import Inventory, Severity
from .registry import all_checks, load_provider
from .reporters import REPORTERS

PROVIDERS = ["azure", "aws"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudguard",
        description="Scan cloud resources for security misconfigurations.",
    )
    parser.add_argument("--version", action="version", version=f"cloudguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run checks against a cloud account or a saved inventory")
    scan.add_argument(
        "--provider",
        default="azure",
        choices=PROVIDERS,
        help="cloud to scan (ignored with --inventory, which records its own provider)",
    )
    scan.add_argument(
        "--subscription-id",
        default=os.environ.get("AZURE_SUBSCRIPTION_ID"),
        help="Azure subscription ID (default: $AZURE_SUBSCRIPTION_ID)",
    )
    scan.add_argument(
        "--region",
        nargs="+",
        metavar="REGION",
        help="AWS region(s) to scan for regional resources (default: your configured region)",
    )
    scan.add_argument(
        "--all-regions", action="store_true", help="AWS: scan every enabled region"
    )
    scan.add_argument("--profile", help="AWS: named profile from your AWS config")
    scan.add_argument(
        "--iac",
        metavar="PATH",
        help="scan Terraform (.tf) files in a file or folder; needs no cloud account",
    )
    scan.add_argument(
        "--inventory",
        metavar="FILE",
        help="scan a saved inventory JSON instead of calling the cloud API (works offline)",
    )
    scan.add_argument(
        "--save-inventory",
        metavar="FILE",
        help="write the collected inventory to FILE so the scan can be replayed offline",
    )
    scan.add_argument("--format", choices=sorted(REPORTERS), default="console")
    scan.add_argument("--output", "-o", metavar="FILE", help="write the report to FILE")
    scan.add_argument(
        "--min-severity",
        default="info",
        help="only report findings at or above this severity (default: info)",
    )
    scan.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        help="exit with status 1 if any finding is at or above this severity",
    )
    scan.add_argument("--only", nargs="+", metavar="CHECK_ID", help="run only these checks")
    scan.add_argument("--skip", nargs="+", metavar="CHECK_ID", help="skip these checks")

    listing = sub.add_parser("list-checks", help="show every available check")
    listing.add_argument("--provider", choices=PROVIDERS, help="only this provider (default: all)")

    return parser


def _cmd_list_checks(args: argparse.Namespace) -> int:
    for provider in [args.provider] if args.provider else PROVIDERS:
        load_provider(provider)
    for registered in all_checks(args.provider):
        meta = registered.meta
        cis = ",".join(meta.cis) or "-"
        mitre = ",".join(meta.mitre) or "-"
        print(f"{meta.id}  {str(meta.severity):8}  CIS {cis:6}  {mitre:18}  {meta.title}")
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    min_severity = Severity.parse(args.min_severity)
    fail_on = Severity.parse(args.fail_on) if args.fail_on else None

    if args.iac and args.inventory:
        print("error: use either --iac or --inventory, not both", file=sys.stderr)
        return EXIT_ERROR
    if args.iac and args.save_inventory:
        print("error: --save-inventory is not supported with --iac", file=sys.stderr)
        return EXIT_ERROR

    if args.iac:
        from .iac.terraform import load_inventories

        inventories = load_inventories(args.iac)
    elif args.inventory:
        inventories = [Inventory.load(args.inventory)]
    elif args.provider == "aws":
        from .providers.aws.collector import collect as collect_aws

        inventories = [
            collect_aws(regions=args.region, profile=args.profile, all_regions=args.all_regions)
        ]
    else:
        if not args.subscription_id:
            print(
                "error: provide --subscription-id (or set AZURE_SUBSCRIPTION_ID), "
                "or scan Terraform with --iac, or a saved file with --inventory",
                file=sys.stderr,
            )
            return EXIT_ERROR
        from .providers.azure.collector import collect as collect_azure

        inventories = [collect_azure(args.subscription_id)]

    if args.save_inventory:
        inventories[0].save(args.save_inventory)

    result = merge_results(
        [
            run_scan(inv, min_severity=min_severity, only=args.only, skip=args.skip)
            for inv in inventories
        ]
    )
    report = REPORTERS[args.format](result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report)

    if result.warnings:
        print(
            f"warning: {len(result.warnings)} collection warning(s); some settings or files "
            "were skipped (shown in the console and JSON reports)",
            file=sys.stderr,
        )
    if result.errors:
        print(f"warning: {len(result.errors)} check(s) failed to run", file=sys.stderr)
    if fail_on is not None and any(f.severity >= fail_on for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "list-checks":
            return _cmd_list_checks(args)
        return _cmd_scan(args)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
