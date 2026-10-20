"""Explicit archived source selection; shared sample identity is report-asserted."""
from dataclasses import dataclass

from .cape import CapeReport, parse_cape_report
from .case_store import open_case, source_identity
from .semantic import SemanticError


@dataclass(frozen=True)
class HistoricalSource:
    case_id: str
    sample_sha256: str
    current_report_sha256: str
    report: CapeReport


def load_historical_source(database, case_id, current_report, current_raw):
    if database is None:
        raise SemanticError('Historical context requires startup --case-db')
    current_identity = source_identity(current_raw)
    if current_identity['report_sha256'] != current_report.source_sha256:
        raise SemanticError('Current source identity changed before history selection')
    if current_identity['sample_sha256'] is None:
        raise SemanticError('Current report has no valid target sample SHA-256 for historical context')
    try:
        metadata, raw, _ = open_case(database, case_id)
    except ValueError as exc:
        raise SemanticError('Historical source is unavailable or inconsistent; model was not called') from exc
    if metadata['sample_sha256'] != current_identity['sample_sha256']:
        raise SemanticError('Historical report does not assert the same target sample SHA-256')
    if metadata['synthetic'] != current_report.synthetic:
        raise SemanticError('Historical and current report synthetic labels differ')
    if metadata['report_sha256'] == current_report.source_sha256:
        raise SemanticError('Select a distinct historical report, not another ruleset for this source')
    return HistoricalSource(metadata['case_id'], metadata['sample_sha256'], current_report.source_sha256,
                            parse_cape_report(raw, synthetic=metadata['synthetic']))
