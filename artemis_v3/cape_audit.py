"""Offline, content-free structural profile for a selected CAPE JSON report.

This is a compatibility aid, not a sanitizer or a malware verdict. It never
prints source strings, evidence IDs, hashes, file paths or model explanations.
Counts and field presence can themselves be sensitive; review before sharing.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import sys

from .cape import CapeReportError, SUMMARY_FIELDS, load_cape_report

PROFILE_VERSION = 'cape-compatibility-profile/1'


def build_profile(report, *, cape_version: str | None = None) -> dict:
    """Summarize normalized evidence without copying report-provided values."""
    parsed = report.as_dict()
    categories = Counter(item.category for item in report.evidence)
    clocks = parsed.get('timeline', {})
    # Parser-defined fixed field names only. Never include untrusted source strings.
    coverage = {
        field: {
            'state': report.behavior_summary[field]['state'],
            'record_count': report.behavior_summary[field]['record_count'],
        }
        for field in SUMMARY_FIELDS
    }
    return {
        'profile_version': PROFILE_VERSION,
        'accepted': True,
        'parser_schema': report.schema_version,
        'parse_status': parsed['status'],
        'operator_declared_cape_version': cape_version,
        'evidence_counts': dict(sorted(categories.items())),
        'process_link_count': len(report.process_links),
        'timeline_counts': {
            clock: len(clocks.get(clock, [])) for clock in ('utc', 'report_clock', 'undated')
        },
        'summary_field_coverage': coverage,
        'warning_count': len(report.warnings),
        'interpretation': ('Field presence and counts are source assertions, not unique actions, '
                           'successful execution, malware verdicts or real CAPE compatibility proof.'),
        'sharing_notice': 'Metadata can still be sensitive; review locally before sharing.',
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog='python -m artemis_v3.cape_audit',
        description='Print a local CAPE field-coverage profile without report content')
    parser.add_argument('--report', required=True, help='Existing local CAPE report.json (read only)')
    parser.add_argument('--cape-version', default=None,
                        help='Optional operator-declared CAPE version (not verified by the tool)')
    args = parser.parse_args(argv)
    if args.cape_version is not None and (
        len(args.cape_version) > 120 or not args.cape_version.isprintable()
    ):
        parser.error('--cape-version must be printable and at most 120 characters')
    try:
        report = load_cape_report(args.report)
        result = build_profile(report, cape_version=args.cape_version)
    except (CapeReportError, OSError, ValueError, TypeError, KeyError):
        # Do not print the exception, which could contain an input path or value.
        result = {
            'profile_version': PROFILE_VERSION,
            'accepted': False,
            'error_code': 'report_not_accepted',
            'sharing_notice': 'No source content was included in this response.',
        }
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
