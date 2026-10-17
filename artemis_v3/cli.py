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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="artemis-v3", description="Evidence-first IOC investigation")
    parser.add_argument("indicator", nargs="?", help="MD5, SHA1, SHA256, IPv4/IPv6 address, or domain")
    parser.add_argument("--source", choices=("demo", "virustotal"), default="demo",
                        help="Demo is offline synthetic data; virustotal makes an external query")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--cape-report", help="Read a local CAPE JSON report offline (10 MiB maximum)")
    parser.add_argument("--synthetic", action="store_true", help="Label an imported report as synthetic")
    parser.add_argument("--ruleset", help="Explicit local signature ruleset JSON for offline CAPE scoring research")
    args = parser.parse_args(argv)
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
