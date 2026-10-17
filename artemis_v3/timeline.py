"""Derived process/API chronology; never invent time zones or causal links."""
from datetime import datetime, timezone
import re

_TIMESTAMP = re.compile(
    r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}'
    r'(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?\Z', re.ASCII)


def normalize_timestamp(value):
    """Return (clock, ISO timestamp); undated records retain raw data elsewhere."""
    if value is None:
        return 'missing', None
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return 'invalid', None
    # datetime accepts offset minutes >59 by normalizing them; reject those.
    if value[-6:-5] in ('+', '-') and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        return 'invalid', None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            return 'report_clock', parsed.isoformat(timespec='microseconds')
        return 'utc', parsed.astimezone(timezone.utc).isoformat(timespec='microseconds')
    except (ValueError, OverflowError):
        return 'invalid', None


def build_timeline(evidence):
    """Separate clock domains; stable ordering of ties is not execution ordering."""
    groups = {'utc': [], 'report_clock': [], 'undated': []}
    for item in evidence:
        if item.category == 'process':
            field, kind = 'first_seen', 'process_first_seen'
        elif item.category == 'api_call':
            field, kind = 'timestamp', 'api_call'
        else:
            continue
        clock, normalized = normalize_timestamp(item.data.get(field))
        event = {
            'evidence_ref': item.evidence_id,
            'process_ref': item.process_ref if kind == 'api_call' else item.evidence_id,
            'kind': kind,
            'timestamp_pointer': item.source_pointer + '/' + field if field in item.data else None,
            'time_status': clock,
            'normalized_time': normalized,
        }
        groups[clock if clock in ('utc', 'report_clock') else 'undated'].append(event)
    for clock in ('utc', 'report_clock'):
        groups[clock].sort(key=lambda event: event['normalized_time'])
    return {
        'scope': 'Process first_seen and API timestamps only; not a complete execution timeline.',
        'ordering': 'Each clock domain sorted separately; ties retain source order, not causal order.',
        'clock_caveat': 'report_clock has no known timezone; clock accuracy/synchronization is unverified.',
        **groups,
    }
