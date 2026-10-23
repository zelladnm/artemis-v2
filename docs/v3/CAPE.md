# Offline CAPE evidence import

Import an existing synthetic or redacted CAPE JSON report. No GPU, model,
network, sandbox, sample execution or third-party packages are needed.

```sh
python -m artemis_v3 --cape-report tests/fixtures/cape_synthetic.json --synthetic --format json
python -m artemis_v3 --cape-report /path/to/redacted-report.json
python -m unittest discover -s tests -p 'test_v3*.py' -v
```

`--cape-report` excludes IOC lookup and external providers. `--synthetic` is an
explicit operator label, not inferred from untrusted report metadata. Successful
imports return exit code 0 even with coverage warnings (`status: partial`);
invalid inputs return 2. Parsing success never means a sample is benign.

## Supported subset

| Input | Output |
|---|---|
| `behavior.processes[]` | Source process metadata; calls become separate evidence |
| `behavior.processes[].calls[]` | API evidence with process references; source parameters, status, return and repetition retained |
| `process_id`, `parent_id` | Unambiguous reported-parent links; never injection claims |
| `behavior.processes[].file_activities.{read_files,write_files,delete_files}[]` | File paths with explicit process evidence references |
| `behavior.summary.{files,read_files,write_files,delete_files}[]` | Unattributed file activity; no fabricated process or timestamp |
| `behavior.summary.{keys,read_keys,write_keys,delete_keys}[]` | Registry summary strings with original field/index references |
| `behavior.summary.{created_services,started_services}[]` | Service summary strings; membership does not establish successful creation/start |
| `behavior.summary.executed_commands[]` | Literal command-line summary strings; never executed by Artemis |
| `behavior.summary.mutexes[]` | Mutex summary strings; no inferred owning process or malware family |
| `behavior.summary.resolved_apis[]` | Source-reported resolved API strings; no inferred API execution |
| `dropped[]` | Source-reported dropped-file metadata |
| `network.{dns,http,tcp,udp}[]` | Source-reported network records; no fabricated PID correlation |
| `signatures[]` | Source assertions preserved, not independent detections or scores |

The adapter uses `process_id`/`parent_id` as nonnegative JSON integers. Duplicate
PIDs, absent parents, and cycles generate diagnostics; ambiguous links are
omitted. PID reuse requires a later lifecycle-aware adapter. Process `first_seen` and API `timestamp` values are preserved in evidence and normalized into separate clock domains; this is not a complete timeline.

Every evidence record has the exact source-byte SHA-256 plus an RFC 6901 JSON
pointer. Whitespace changes the source digest intentionally. Keep the original
JSON alongside the normalized result for independent verification. The importer
does not copy or persist the original file. A digest identifies bytes, not source
trustworthiness. Summary and process file records may overlap; no counts should
be interpreted as unique actions without a later deduplication policy.

## Limits and interpretation

Input is limited to 10 MiB, 200,000 JSON value nodes, depth 64, and 20,000 normalized
records. Oversize/deep/invalid input fails atomically. Duplicate keys and nonfinite
numbers are rejected. Missing supported sections produce explicit coverage
warnings; malformed supported containers fail. Unknown fields remain outside the
adapter contract. API call objects require nonempty `api` names; optional `arguments` must be an array of objects and `repeated` a nonnegative integer. Missing calls produce a coverage warning; malformed calls fail atomically.
No report-provided paths, URLs or commands are dereferenced. Raw strings remain
untrusted data, including for any future LLM prompt or UI. Markdown export escapes
HTML, backticks and control characters; JSON retains data for downstream handling.

This is a bounded in-memory reader, not a hostile-file sandbox or streaming parser.
Use regular local report files. Large original reports require a future streaming
adapter; do not silently truncate them. Raw BSON, PCAP, memory dumps, screenshots,
higher-level registry interpretation, ATT&CK mapping, scoring and model calls are outside this delivery.

All committed fixtures are synthetic. Compatibility with deployed CAPE versions
and accuracy on real investigations remain unverified.

## Source contract references

Checked against the upstream documentation and behavior processing source during
implementation; no upstream code was copied:

- https://capev2.readthedocs.io/en/latest/customization/reporting.html
- https://capev2.readthedocs.io/en/latest/customization/processing.html
- https://github.com/kevoreilly/CAPEv2/blob/master/modules/processing/behavior.py

CAPE reporting serializes processing results. This adapter reads selected processed
fields; it does not reproduce the thesis's raw filesystem forensic collection.

## Process and API chronology (schema cape-evidence/2)

```sh
python -m artemis_v3 --cape-report tests/fixtures/cape_timeline_synthetic.json --synthetic --format json
```

The version changes from `cape-evidence/1` to `/2`: API calls are now evidence and
`timeline` is added to JSON/Markdown output. Existing process evidence still excludes
`calls`. Consumers must accept the new `api_call` category. Record limits include
API calls; oversized reports fail rather than dropping calls.

Timeline entries reference original evidence and timestamp JSON pointers. A missing
field has no pointer. Invalid/null source timestamps remain in evidence. Missing or
invalid process/API times produce coverage warnings and an `undated` entry.

- `utc`: explicitly offset timestamps normalized to UTC, sorted chronologically.
- `report_clock`: timestamps without timezone, sorted as reported wall-clock values.
  No host timezone is assumed. Cross-process clock synchronization is unverified.
- `undated`: missing, unsupported or invalid timestamps in source order.

No total ordering is asserted between these domains. Equal timestamps retain source
order for reproducibility, not causality. Supported strings have date and full time,
optional 1–6 fractional digits, and optional `Z`/`+HH:MM`/`-HH:MM`. Epoch numbers,
date-only strings and invalid calendars are not guessed. File/network summaries
remain evidence outside this process/API timeline; their timestamps are not inferred.

Each call links to its containing process record, not a PID lookup. `first_seen`
means first observed, not proven process creation. Status and return values remain
source assertions; even `NtWriteVirtualMemory` is not automatically an injection
finding. Compressed `repeated` values remain on one call record, with no invented
individual timestamps or expanded execution count.

The new fixture contains failed calls, reused PIDs, mixed clocks and unknown times.
It is synthetic and does not establish real-version compatibility or detection
accuracy. No API execution, external lookup or scoring is introduced.

## Behavior summary coverage (schema cape-evidence/3)

The current adapter extends /2 with `registry_summary`, `service_summary`,
`command_summary`, `mutex_summary` and `resolved_api_summary`. Each record has
`reported_operation` (the original field) and `value` (the exact source string).
Existing file summaries retain `path` and their evidence IDs. Consumers must
accept /3, the new categories and `behavior_summary`; database formats do not change.

For each of the 13 supported summary fields, `behavior_summary` records
`source_pointer`, `record_count` and a state:

| State | Meaning |
|---|---|
| `absent` | Field absent; coverage unknown. Count 0 does not establish no activity. |
| `empty` | An explicitly empty list; no entry listed by that processor. |
| `reported` | Strings listed; count describes records, not unique or successful actions. |

Malformed supported fields, including null containers and non-string values,
fail atomically. Previously ignored malformed new fields now fail under /3.
Unknown fields remain outside the contract. Missing newly supported fields appear
in this coverage map instead of adding redundant warnings to older reports.
Existing warnings and partial/parsed status retain their previous meanings.

Values, duplicates, case and Unicode are preserved. Identical strings at separate
indices/lists retain separate provenance. No PID association, timeline event,
automatic ATT&CK mapping, persistence conclusion or score change is inferred.
The synthetic fixture lists a service alongside a failed CreateServiceW call;
these remain independent source assertions, with the call's false status intact.

The workbench's 行为汇总 view groups six evidence families and links to exact
records. Each group shows at most 20 entries with a category-filtered browser for
the rest; the existing browser displays at most 200 matches. Full normalized
records remain in JSON. HTML/Markdown include compact coverage groups and source
excerpts under existing appendix limits. Explicitly select summaries needed in
model context; record/byte budgets and omission disclosures still apply.

Contract audit on 2026-10-23 used CAPEv2 commit
`b14817d0689a5183abbc7666e51d222ef03b039e`:

- [behavior.py](https://github.com/kevoreilly/CAPEv2/blob/b14817d0689a5183abbc7666e51d222ef03b039e/modules/processing/behavior.py): Summary.run() emits the supported lists; service-summary membership does not guarantee call success.
- [jsondump.py](https://github.com/kevoreilly/CAPEv2/blob/b14817d0689a5183abbc7666e51d222ef03b039e/modules/reporting/jsondump.py): serializes processed results to report.json.

No upstream implementation was copied, imported or executed. All new committed
reports are synthetic, shaped from this field contract. This audit does not
establish compatibility with real deployed reports or real model quality.
Archives retain exact bytes and reopen with the current parser. Saved explanations
can reopen when their cited evidence and rule score still match; new unrelated
summary records do not invalidate those citations. Old evaluation runs still need
their matching implementation, as documented in EVALUATION_REVIEW.md.
