# Local analyst review history

This workflow records an analyst's decision about a score adjustment proposal. It
recomputes the deterministic assessment and proposal from the selected original
report and ruleset, and binds both source fingerprints. It does not call a model,
execute a sample or upload evidence.

## Prepare and record a decision

From the repository root, emit an assessment plus a blank request template:

```sh
python -m artemis_v3 --cape-report tests/fixtures/cape_synthetic.json --synthetic --ruleset tests/fixtures/scoring_synthetic.json --review-template --format json
```

Copy the `review_request_template` object into a local JSON file. Choose a delta,
cite 1–32 evidence IDs from `report.evidence`, and fill the rationale, reviewer,
decision and reason. The blank template intentionally cannot be submitted. It
already includes the report/ruleset fingerprints so they need not be transcribed.

| Request field | Meaning |
|---|---|
| `source_sha256`, `ruleset_sha256` | Exact original report/catalog bytes selected for this review |
| `delta` | Integer proposal from -10 through 10; not automatically applied |
| `cited_evidence` | Distinct evidence IDs from this report |
| `rationale` | Why the adjustment was proposed, at most 500 characters |
| `reviewer` | Local declared analyst identifier, at most 100 characters |
| `decision` | `approve`, `reject`, or `defer` |
| `reason` | Analyst decision reason, at most 1000 characters |
| `expected_previous_id` | `null` for the first decision on this exact proposal; otherwise the latest review ID |

All fields are required. Unexpected fields, duplicate JSON keys and request files
over 32 KiB are rejected. Report and catalog fingerprints must match the inputs.

Record and then inspect history, substituting paths you explicitly selected:

```sh
python -m artemis_v3 --cape-report tests/fixtures/cape_synthetic.json --synthetic --ruleset tests/fixtures/scoring_synthetic.json --review-request /path/to/request.json --review-db /path/to/reviews.sqlite --format json
python -m artemis_v3 --review-history /path/to/reviews.sqlite --format json
```

Only the explicit request/database option pair writes history. Preparation and
investigation without it do not create a database. History reads use a read-only
connection; the CLI returns up to 100 recent records, newest first. The Python
`list_reviews` API can filter by proposal fingerprint and select a limit of 1–1000.
Keep the database outside the Git checkout when it contains real investigations.

## Score and revision behavior

- Every record preserves the assessment, proposal, evidence citations, source and
  catalog fingerprints, declared reviewer, UTC recording time and decision reason.
- `base_score` and the proposal's `applied_score` retain the deterministic score.
  `analyst_score` is populated only for an explicitly approved proposal. Neither is
  a malware verdict. Original evidence is never rewritten.
- A critical negative proposal cannot be approved through this workflow. It can
  be rejected or deferred. Changing the rule catalog creates a different context
  and does not silently revise an earlier record.
- A decision appends a new revision for the exact proposal. Submit the latest
  `review_id` as `expected_previous_id` to revise it, including after a defer.
  SQLite serializes writes; stale or simultaneous first decisions cannot both
  succeed. Changed proposal rationale, delta or citations creates a new proposal,
  not an in-place edit. There is no single synthesized verdict across proposals.

The database uses an application marker and schema version, refuses unrelated
stores, and appends decisions transactionally. Each body has a SHA-256 checksum
checked during reads. This detects accidental inconsistency; it is not a digital
signature or proof against a person who can modify the database and its checksum.
The API does not delete or update historical records. Store copies of the original
report and ruleset separately; the database keeps review snapshots and citations,
not the full original files.

## Current boundaries

Reviewer names are self-declared local identifiers. Login, role enforcement,
external signatures, multi-party approval and an analyst UI remain future work.
This is a local review record, not an authenticated enterprise authorization
system. SQLite files supplied by others are outside the trusted local-store
boundary. Tests use only synthetic evidence and temporary databases.
