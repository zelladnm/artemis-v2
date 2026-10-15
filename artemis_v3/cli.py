"""Zero-dependency CLI: offline demonstration or explicitly enabled live lookup."""
from __future__ import annotations

import argparse
import json

from .engine import investigate
from .providers import DemoProvider, VirusTotalProvider


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="artemis-v3", description="Evidence-first IOC investigation")
    parser.add_argument("indicator", help="MD5, SHA1, SHA256, IPv4/IPv6 address, or domain")
    parser.add_argument("--source", choices=("demo", "virustotal"), default="demo",
                        help="Demo is offline synthetic data; virustotal makes an external query")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args(argv)
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
