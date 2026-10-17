"""Bounded, offline normalization of a documented subset of CAPE report.json.

All records are source assertions, not verified behavior or malware verdicts.
No report-provided path, URL, command, or attachment is opened or executed.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import html
import json
from pathlib import Path
import math

from .timeline import build_timeline

MAX_BYTES = 10 * 1024 * 1024
MAX_NODES = 200_000
MAX_DEPTH = 64
MAX_RECORDS = 20_000


class CapeReportError(ValueError):
    """Invalid or unsupported report, with a safe diagnostic."""


@dataclass(frozen=True)
class BehaviorEvidence:
    evidence_id: str
    category: str
    source_pointer: str
    data: dict
    process_ref: str | None = None


@dataclass
class CapeReport:
    source_sha256: str
    synthetic: bool
    evidence: list[BehaviorEvidence] = field(default_factory=list)
    process_links: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    schema_version: str = 'cape-evidence/2'

    def as_dict(self) -> dict:
        result = asdict(self)
        result['status'] = 'partial' if self.warnings else 'parsed'
        result['verdict'] = 'not_assessed'
        result['timeline'] = build_timeline(self.evidence)
        result['scope'] = 'Selected CAPE JSON fields only; retain the original report.'
        return result

    def as_markdown(self) -> str:
        # Escape all untrusted content; never render report strings as links/HTML.
        payload = html.escape(json.dumps(self.as_dict(), ensure_ascii=True, indent=2))
        payload = payload.replace('`', '&#96;')
        label = '\n**SYNTHETIC DEMO DATA**\n' if self.synthetic else ''
        return ('# Artemis v3 — CAPE evidence\n' + label +
                '\nSource assertions only. No malware verdict. Missing evidence does not mean benign.\n'
                '\n<pre>' + payload + '</pre>\n')


def _pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CapeReportError('Duplicate JSON object keys are not accepted')
        result[key] = value
    return result


def _constant(value: str):
    raise CapeReportError('Non-finite JSON numbers are not accepted')


def _validate_tree(root) -> None:
    stack = [(root, 0)]
    count = 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise CapeReportError('Report exceeds structural limits')
        if isinstance(value, float) and not math.isfinite(value):
            raise CapeReportError('Non-finite JSON numbers are not accepted')
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)


def load_cape_report(path: str | Path, *, synthetic: bool = False) -> CapeReport:
    """Read at most MAX_BYTES + 1 from an explicitly selected local JSON file."""
    path = Path(path)
    if not path.is_file():
        raise CapeReportError('CAPE input must be a regular local file')
    try:
        with path.open('rb') as source:
            raw = source.read(MAX_BYTES + 1)
    except OSError as exc:
        raise CapeReportError('Cannot read CAPE report') from exc
    return parse_cape_report(raw, synthetic=synthetic)


def parse_cape_report(raw: bytes, *, synthetic: bool = False) -> CapeReport:
    """Parse report bytes; exact-byte digest and JSON pointers identify evidence.

    Missing optional sections produce explicit coverage warnings. Malformed
    supported fields are rejected atomically rather than silently discarded.
    """
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise CapeReportError('Expected JSON bytes within the 10 MiB limit')
    try:
        root = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_pairs,
                          parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CapeReportError('Invalid JSON report: encoding, structure, keys or numbers') from exc
    _validate_tree(root)
    if not isinstance(root, dict) or not any(k in root for k in ('behavior', 'network', 'signatures', 'dropped')):
        raise CapeReportError('Expected a CAPE report object with supported sections')
    result = CapeReport(hashlib.sha256(raw).hexdigest(), synthetic)

    def obj(value, pointer):
        if not isinstance(value, dict):
            raise CapeReportError(f'{pointer}: expected object')
        return value

    def array(parent, key, pointer):
        if key not in parent:
            result.warnings.append(f'{pointer}: absent; coverage unknown')
            return []
        if not isinstance(parent[key], list):
            raise CapeReportError(f'{pointer}: expected array')
        return parent[key]

    def add(category, pointer, data, process_ref=None):
        if len(result.evidence) >= MAX_RECORDS:
            raise CapeReportError('Report exceeds evidence record limit')
        eid = result.source_sha256 + '#' + pointer
        result.evidence.append(BehaviorEvidence(eid, category, pointer, data, process_ref))
        return eid

    behavior = obj(root.get('behavior', {}), '/behavior')
    network = obj(root.get('network', {}), '/network')
    processes = array(behavior, 'processes', '/behavior/processes')
    by_pid = {}
    process_rows = []
    for i, process in enumerate(processes):
        pointer = f'/behavior/processes/{i}'
        process = obj(process, pointer)
        pid = process.get('process_id')
        ppid = process.get('parent_id')
        if type(pid) is not int or pid < 0:
            raise CapeReportError(f'{pointer}/process_id: expected nonnegative integer')
        if ppid is not None and (type(ppid) is not int or ppid < 0):
            raise CapeReportError(f'{pointer}/parent_id: expected nonnegative integer')
        eid = add('process', pointer, {k: v for k, v in process.items() if k != 'calls'})
        by_pid.setdefault(pid, []).append(eid)
        process_rows.append((pid, ppid, eid))
        activities = obj(process.get('file_activities', {}), pointer + '/file_activities')
        for operation in ('read_files', 'write_files', 'delete_files'):
            if operation not in activities:
                continue
            activity_path = pointer + '/file_activities/' + operation
            for index, value in enumerate(array(activities, operation, activity_path)):
                if not isinstance(value, str):
                    raise CapeReportError(f'{activity_path}/{index}: expected string path')
                add('process_file_activity', f'{activity_path}/{index}',
                    {'reported_operation': operation, 'path': value}, process_ref=eid)
        for index, call in enumerate(array(process, 'calls', pointer + '/calls')):
            call_pointer = f'{pointer}/calls/{index}'
            call = obj(call, call_pointer)
            if not isinstance(call.get('api'), str) or not call['api'].strip():
                raise CapeReportError(f'{call_pointer}/api: expected nonempty string')
            if 'arguments' in call:
                for arg_index, arg in enumerate(array(call, 'arguments', call_pointer + '/arguments')):
                    obj(arg, f'{call_pointer}/arguments/{arg_index}')
            if 'repeated' in call and (type(call['repeated']) is not int or call['repeated'] < 0):
                raise CapeReportError(f'{call_pointer}/repeated: expected nonnegative integer')
            # Preserve status/return/arguments verbatim. A call alone proves neither
            # success nor injection. Repeated calls stay one source record.
            add('api_call', call_pointer, call, process_ref=eid)
    # Only unambiguous PID relations become links. PID reuse is not resolved by guessing.
    parents = {pid: ppid for pid, ppid, _ in process_rows if len(by_pid[pid]) == 1}
    # Memoize cycle reachability so a long process chain remains linear-time.
    cycle_reachable = {}
    for start in parents:
        trail = set()
        current = start
        while current in parents and current not in trail and current not in cycle_reachable:
            trail.add(current)
            current = parents[current]
        cyclic = current in trail or cycle_reachable.get(current, False)
        for visited in trail:
            cycle_reachable[visited] = cyclic
    for pid, ppid, eid in process_rows:
        if len(by_pid[pid]) != 1:
            result.warnings.append(f'{eid}: duplicate PID; parent relation unresolved')
            continue
        if ppid is None:
            result.warnings.append(f'{eid}: missing parent ID')
            continue
        if ppid not in by_pid:
            if ppid != 0:
                result.warnings.append(f'{eid}: parent not present in report')
            continue
        if len(by_pid[ppid]) != 1:
            result.warnings.append(f'{eid}: ambiguous parent PID')
            continue
        if cycle_reachable[pid]:
            result.warnings.append(f'{eid}: cyclic parent relation; link omitted')
            continue
        result.process_links.append({'parent_ref': by_pid[ppid][0], 'child_ref': eid,
                                     'relation': 'reported_parent', 'source_pointer': eid.split('#', 1)[1] + '/parent_id'})

    summary = obj(behavior.get('summary', {}), '/behavior/summary')
    for key in ('files', 'read_files', 'write_files', 'delete_files'):
        if key not in summary:
            continue
        for i, value in enumerate(array(summary, key, f'/behavior/summary/{key}')):
            pointer = f'/behavior/summary/{key}/{i}'
            if not isinstance(value, str):
                raise CapeReportError(f'{pointer}: expected string path')
            add('file_summary', pointer, {'reported_operation': key, 'path': value})
    if not any(k in summary for k in ('files', 'read_files', 'write_files', 'delete_files')):
        result.warnings.append('/behavior/summary: supported file activity fields absent')
    for key, category in (('dropped', 'dropped_file'), ('signatures', 'signature')):
        for i, value in enumerate(array(root, key, '/' + key)):
            pointer = f'/{key}/{i}'
            add(category, pointer, obj(value, pointer))
    for key in ('dns', 'http', 'tcp', 'udp'):
        for i, value in enumerate(array(network, key, '/network/' + key)):
            pointer = f'/network/{key}/{i}'
            add('network_' + key, pointer, obj(value, pointer))
    undated = build_timeline(result.evidence)['undated']
    if undated:
        result.warnings.append(f'Timeline: {len(undated)} process/API records have missing or invalid timestamps; retained as undated')
    return result
