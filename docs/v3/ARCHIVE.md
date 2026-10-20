# Local source archive and exact hash lookup

The workbench can explicitly retain CAPE report and ruleset bytes in a local
SQLite archive, find previous reports by exact hashes and reopen them after a
page/server restart. This reduces repeated file selection and establishes the
source identity layer for later knowledge retrieval.

## Enable and use

Choose a new or existing Artemis archive path outside the checkout. Its parent
directory must exist. Review history uses a separate database:

```sh
python -m artemis_v3.workbench --case-db ../artemis-cases.sqlite --review-db ../artemis-reviews.sqlite
```

Startup, investigation and reading an empty archive create no database. Saving
requires clicking **归档来源** after importing a report or loading the demo. An
optional title can be entered under **本地调查归档**. This action persists the
original report/ruleset bytes, their fingerprints, synthetic labels and metadata.
The usual 10 MiB report and 64 KiB ruleset limits apply. Reports without a ruleset
can also be archived.

Expand **本地调查归档**, then choose recent records or enter a complete SHA-256.
Select the hash type explicitly:

| Lookup type | Meaning |
|---|---|
| Report original-byte SHA-256 | Exact identity of the entire JSON byte sequence |
| Report-declared sample SHA-256 | Exact match against `/target/file/sha256` asserted by a report |

Uppercase hexadecimal is normalized. Prefixes, filenames, MD5/SHA1 values and fuzzy
matches are refused. Missing/invalid target hashes remain unknown; the report
fingerprint is never substituted for a sample hash. This workflow has no sample
bytes and cannot independently verify the report's sample identity. Equal reported
sample hashes may return multiple distinct reports, rule versions or labels.

Click **重新打开** to load archived bytes and recompute normalized evidence,
process links, timelines and rule scores with the current implementation. The UI
restores the synthetic label and shows both hash types separately. Original source
filenames are unnecessary because provenance is based on bytes. A report that
cannot be validated by the current parser fails to reopen with an explicit error.

Archive identity consists of report fingerprint, optional ruleset fingerprint and
the report's synthetic label. A different report, ruleset or synthetic label gets
a separate immutable record. Re-saving the same tuple is idempotent: it returns
the existing creation time/title rather than replacing it. The first title is
retained; this version provides no rename/delete operation. Recent and exact
queries display at most 50 metadata records, newest first, and disclose that cap.

## Investigation state and knowledge scope

Reopening restores sources and recomputes derived results. Use JSON/Markdown
export to retain model explanations and the current review result separately;
analyst review history continues to use `--review-db` and **刷新历史**. Archival
does not invoke a model or automatically apply historical analyst decisions.

Exact retrieval is a source lookup capability. Semantic similarity, automatic
historical context injection into model prompts, case verdict inheritance and a
full RAG system remain future work. A returned historical report remains an
unverified source assertion. Any future model context must preserve its report,
sample-identity provenance, synthetic label and independent evidence citations.

## Storage and API boundaries

The archive has its own application/schema markers and refuses unrelated or
unsupported SQLite stores. A write transaction protects duplicate saves and
budget checks across concurrent writers. The initial limits are 1,000 records and
128 MiB of original report/ruleset payloads. This is a payload budget, not a strict
database/journal filesystem quota. Back up the local database with the server
stopped or a SQLite-aware backup process before modifying its storage externally.

Metadata checksums and indexed identities are checked on listing. Reopening also
validates source sizes, reparses the original bytes and verifies stable source
identity fields against the stored record. List counts describe archival time;
current parser counts/coverage may evolve and are recomputed when opened.
Corrupt/inconsistent source identities are
refused. Checksums are not authentication or protection from a database owner.
List queries return metadata rather than complete source blobs, and oversized
stored blobs are refused before loading into Python. The local service trust
boundary and privacy expectations in [WORKBENCH.md](WORKBENCH.md) still apply.

The server-owned `--case-db` path is never supplied by the browser. Token/Host/
Origin guards and JSON request limits apply to all archive routes. API requests:

- `GET /api/cases`: recent metadata.
- `POST /api/cases/search`: exactly `kind` (`sample` or `report`) and `sha256`.
- `POST /api/cases/save`: report/ruleset base64 bytes, synthetic label and optional
  `archive_title`; returns a case identity and whether a new record was created.
- `POST /api/cases/open`: exactly `case_id`; returns stored inputs and a recomputed
  workbench result. No report-provided filesystem path or URL is opened.

With no `--case-db`, archive operations return a configuration error while normal
offline investigation remains available. Query misses convey only that no matching
record was returned from this local archive.

## Verification

Synthetic storage/HTTP tests cover exact typed identity, uppercase normalization,
missing/invalid target hashes, source/rules/label variants, duplicate/concurrent
saves, quotas, foreign stores, corruption, guarded routes and model-free reopening.
Chromium CI archives hostile text, reloads the page, looks up the reported sample
hash, reopens original bytes and checks the unchanged rule score on desktop/mobile
flows. Real report compatibility and historical knowledge quality remain unmeasured.
