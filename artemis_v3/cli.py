"""Zero-dependency CLI: offline demonstration or explicitly enabled live lookup."""
from __future__ import annotations

import argparse
import json
import html

from .cape import load_cape_report
from .engine import investigate
from .providers import DemoProvider, VirusTotalProvider
from .ruleset import load_ruleset
from .scoring import assess_signatures
from .review import load_review_request, record_review, list_reviews


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="artemis-v3", description="Evidence-first IOC investigation")
    parser.add_argument("indicator", nargs="?", help="MD5, SHA1, SHA256, IPv4/IPv6 address, or domain")
    parser.add_argument("--source", choices=("demo", "virustotal"), default="demo",
                        help="Demo is offline synthetic data; virustotal makes an external query")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--cape-report", help="Read a local CAPE JSON report offline (10 MiB maximum)")
    parser.add_argument("--synthetic", action="store_true", help="Label an imported report as synthetic")
    parser.add_argument("--ruleset", help="Explicit local signature ruleset JSON for offline CAPE scoring research")
    parser.add_argument("--review-request", help="Explicit local analyst decision JSON (writes only with --review-db)")
    parser.add_argument("--review-db", help="Local SQLite review history destination")
    parser.add_argument("--review-template", action="store_true", help="Include an unfilled review request template")
    parser.add_argument("--review-history", help="Read recent local review history from SQLite")
    args = parser.parse_args(argv)
    if args.review_history:
        if (args.indicator or args.cape_report or args.ruleset or args.review_request or args.review_db
                or args.review_template or args.synthetic or args.source != "demo"):
            parser.error("--review-history must be used without investigation/review input options")
        try:
            records = list_reviews(args.review_history)
        except ValueError as exc:
            parser.error(str(exc))
        rendered = json.dumps({"schema_version": "artemis-review-history/1", "reviews": records},
                              ensure_ascii=True, indent=2)
        print(rendered if args.format == "json" else
              "# Artemis v3 — review history\n<pre>" + html.escape(rendered).replace('`', '&#96;') + "</pre>")
        return 0
    if (args.review_request or args.review_db or args.review_template) and not args.ruleset:
        parser.error("Review input requires --cape-report and --ruleset")
    if bool(args.review_request) != bool(args.review_db):
        parser.error("--review-request and --review-db must be supplied together")
    if args.review_template and args.review_request:
        parser.error("--review-template cannot record a review")
    if args.ruleset and not args.cape_report:
        parser.error("--ruleset requires --cape-report")
    if args.cape_report:
        if args.indicator or args.source != "demo":
            parser.error("--cape-report cannot be combined with an IOC or external provider")
        try:
            report = load_cape_report(args.cape_report, synthetic=args.synthetic)
            if args.ruleset:
                catalog = load_ruleset(args.ruleset)
                assessment = assess_signatures(report, catalog.rules, version=catalog.version)
                result = {"schema_version": "artemis-assessment/1", "report": report.as_dict(),
                          "rule_assessment": assessment.as_dict(),
                          "ruleset_sha256": catalog.source_sha256,
                          "ruleset_synthetic": catalog.synthetic}
                if args.review_template:
                    result["review_request_template"] = {
                        "source_sha256": report.source_sha256, "ruleset_sha256": catalog.source_sha256,
                        "delta": 0, "cited_evidence": [], "rationale": "", "reviewer": "",
                        "decision": "defer", "reason": "", "expected_previous_id": None}
                if args.review_request:
                    request = load_review_request(args.review_request)
                    result["analyst_review"] = record_review(args.review_db, report, catalog, request)
                rendered = json.dumps(result, ensure_ascii=True, indent=2)
                if args.format != "json":
                    label = "\n**SYNTHETIC DEMO DATA**\n" if report.synthetic or catalog.synthetic else ""
                    rendered = ("# Artemis v3 — rule assessment\n" + label +
                                "\nUncalibrated rule points; analyst review required. No malware verdict.\n<pre>" +
                                html.escape(rendered).replace('`', '&#96;') + "</pre>")
                print(rendered)
                return 0
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps(report.as_dict(), ensure_ascii=True, indent=2) if args.format == "json"
              else report.as_markdown(), end="\n")
        return 0
    if not args.indicator or args.synthetic:
        parser.error("Provide an IOC or --cape-report; --synthetic requires --cape-report")
    try:
        provider = DemoProvider() if args.source == "demo" else VirusTotalProvider()
        report = investigate(args.indicator, [provider])
    except ValueError as exc:
        parser.error(str(exc))

    if args.format == "json":
        print(json.dumps(report.as_dict(), ensure_ascii=False, indent=2))
    else:
        print(report.as_markdown(), end="")
    return 1 if report.status == "failed" else 0
