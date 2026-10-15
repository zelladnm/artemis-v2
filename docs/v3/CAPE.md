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
| `behavior.processes[]` | Source process metadata, excluding raw API calls |
| `process_id`, `parent_id` | Unambiguous reported-parent links; never injection claims |
| `behavior.processes[].file_activities.{read_files,write_files,delete_files}[]` | File paths with explicit process evidence references |
| `behavior.summary.{files,read_files,write_files,delete_files}[]` | Unattributed file activity; no fabricated process or timestamp |
| `dropped[]` | Source-reported dropped-file metadata |
| `network.{dns,http,tcp,udp}[]` | Source-reported network records; no fabricated PID correlation |
| `signatures[]` | Source assertions preserved, not independent detections or scores |

The adapter uses `process_id`/`parent_id` as nonnegative JSON integers. Duplicate
PIDs, absent parents, and cycles generate diagnostics; ambiguous links are
omitted. PID reuse requires a later lifecycle-aware adapter. Source timestamps
are preserved as data, not normalized or claimed to be a complete timeline.

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
adapter contract. API calls are not normalized and their presence is flagged.
No report-provided paths, URLs or commands are dereferenced. Raw strings remain
untrusted data, including for any future LLM prompt or UI. Markdown export escapes
HTML, backticks and control characters; JSON retains data for downstream handling.

This is a bounded in-memory reader, not a hostile-file sandbox or streaming parser.
Use regular local report files. Large original reports require a future streaming
adapter; do not silently truncate them. Raw BSON, PCAP, memory dumps, screenshots,
registry events, ATT&CK mapping, scoring and model calls are outside this delivery.

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
