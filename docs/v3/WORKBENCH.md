# Local investigation workbench

Start an offline workbench from the repository root (Python 3.11+, no third-party
runtime dependencies):

```sh
python -m artemis_v3.workbench
```

Open the printed `http://127.0.0.1:8765` address. Use **加载离线演示** to load the
bundled synthetic report and rules. These are demonstration assertions, not a real
malware analysis. By default no model is configured and no AI explanation is generated.
An [opt-in local Ollama adapter](SEMANTIC.md) is now available with explicit
generation, evidence references and analyst review of any adjustment suggestion.

To enable explicit local review persistence, select a database path at startup:

```sh
python -m artemis_v3.workbench --port 8765 --review-db /path/to/reviews.sqlite
```

The parent directory must exist. Starting the server does not create the database;
only saving a review writes it. Keep real investigation data outside the checkout.
Without this option, investigation and export work but review writes are refused.
Use Ctrl+C to stop. Port 0 chooses a free loopback port and prints it.

Optional [source archival and exact SHA-256 lookup](ARCHIVE.md) is enabled with
`--case-db /path/to/cases.sqlite`, using a database separate from review history.
Click **归档来源** to persist report/ruleset bytes, then query and reopen records
under **本地调查归档**. Reopening recomputes evidence and rule results.
With a configured model, a matching distinct archived report can be explicitly
selected for [historical evidence context](HISTORICAL.md) before generation.

## Investigation flow

1. Load the demo or select an existing CAPE JSON report (10 MiB maximum). Optionally
   select a local ruleset (64 KiB) and an untrusted suggestion JSON (32 KiB).
2. Set the synthetic-data checkbox accurately, then start investigation. Files are
   sent only to the local loopback service for the existing bounded parsers. They
   are not uploaded to a third party or executed.
3. Inspect deterministic rule findings and coverage warnings, reported parent-child
   process links, separate clock-domain timelines, and raw evidence JSON pointers.
   Each list is capped for rendering (200 records, 100 overview warnings); filtering
   searches the full normalized evidence. Exports contain all normalized records.
4. Select 1–32 evidence references and enter an adjustment rationale. Alternatively,
   import a suggestion, whose delta/rationale/citations are then locked in the UI.
5. Enter a declared reviewer, approve/reject/defer decision and reason. The service
   recomputes the original report/catalog assessment. A decision about an imported
   suggestion must match its adjustment, and its exact file fingerprint is saved.
6. In the model explanation tab, [review each claim against its evidence](CLAIM_REVIEW.md).
   Save supported/unsupported/uncertain judgments and reasons, leaving untouched claims
   unreviewed. This does not approve any score adjustment.
7. Export JSON or escaped Markdown, including the current review records, if any.
   Read local history to inspect previous decisions and their full snapshots.

The previous review ID protects revisions of the same proposal. A first decision
leaves it blank; saving fills it for the next revision. Editing delta, rationale or
citations starts another proposal, so the UI clears this ID. Duplicate/stale writes
fail rather than overwrite history. The base score is unchanged by all decisions;
any approved analyst score is a separate field. Critical negative proposals cannot
be approved by this workflow. Reviewer identities are self-declared, not logged in.

## Proposal intake integration

The implementation reuses the evidence-bound suggestion validator from commit
`e6acd10` and exposes in-memory parsers for browser uploads. The CLI supports:

```sh
python -m artemis_v3 --cape-report /path/to/report.json --ruleset /path/to/rules.json --proposal-file /path/to/suggestion.json --review-template --format json
```

The suggestion schema is `artemis-proposal/1` with exactly:
`schema_version`, `report_sha256`, `ruleset_sha256`, `ruleset_version`,
`proposed_delta`, `cited_evidence`, and `rationale`. It is validated against the
exact source report, catalog and rule assessment. Importing never applies a score
or creates a review decision. Existing CLI-only usage remains available.

## Local service boundary

The server always binds `127.0.0.1`, never an external interface. It refuses unknown
Host headers, cross-origin requests, cross-site fetches and API requests without
its per-process token. It sends no CORS permission, uses a restrictive CSP and
serves only a fixed asset list. Report text is rendered with DOM textContent rather
than HTML. POSTs require JSON with one Content-Length, no chunked transfer, a
15 MiB envelope bound and a socket timeout. Source parsers retain their own limits.
The browser cannot select arbitrary server filesystem paths or database locations.
No external JavaScript, fonts, trackers or CDN assets are loaded.

Cases are recomputed from supplied bytes for each operation, avoiding shared mutable
case state. By default uploads remain in memory. With explicitly configured stores,
**归档来源** persists original report/catalog bytes and **保存复核记录** persists
review snapshots. **保存逐条核验** persists the exact model explanation and per-claim
judgments in the review store; saved generations can be reopened without a model.
Keep independent original copies and exported explanations.
The server is a local research tool, not a hardened public/multi-user service; local
processes with filesystem/browser access remain within the trust boundary.

## Verification

```sh
python -m unittest discover -s tests -p 'test_v3*.py' -v
```

Real-browser smoke tests run in CI with pinned Playwright tooling installed only
on the runner. The test covers desktop/mobile views, process links, timeline,
evidence selection, persisted reviews, JSON export and hostile text remaining
inert. Screenshots are uploaded as the `workbench-browser-screenshots` artifact.
A second flow uses a test-only Ollama HTTP fixture to check explanation, explicit
proposal intake, rejection and export without changing the rule score.
Both browser flows also save an archive, reload, exact-match a reported sample hash
and reopen the original sources, with hostile titles remaining inert.
A failed browser job must be investigated even when Python unit tests pass.

This environment's browser binary download returned HTML rather than an archive;
local Chromium rendering could not be run. Use the CI browser job and screenshots
for browser-specific verification. All committed reports and test inputs are
synthetic. Real CAPE-version compatibility and malware detection accuracy remain
unverified.

Claim review additionally covers partial judgments, exact generation binding, stale
revision rejection, separate score decisions, page reload/reopening and safe export
of saved records versus unsaved drafts. See CLAIM_REVIEW.md for schema-2 migration.
