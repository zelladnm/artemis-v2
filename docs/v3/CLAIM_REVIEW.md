# Workbench claim support review

The model explanation tab now supports human judgments beside each observation,
hypothesis and score-adjustment rationale. This closes the gap between checking
that a reference exists and deciding whether it actually supports the model's text.
The workbench never assigns these judgments automatically.

Saved judgments can also be explicitly selected for fixed evaluation attempts
and exported through [evaluation review mode](EVALUATION_REVIEW.md). Generation
history queries can filter by the exact output fingerprint before the history
limit, so older matching output reviews remain accessible.

## Use

Start with an explicit local review store, optionally enabling the source archive
and an already installed local model:

```sh
python -m artemis_v3.workbench --review-db /path/to/reviews.sqlite --case-db /path/to/cases.sqlite --ollama-model installed-model-tag
```

1. Import a report and optional rules, then explicitly generate an explanation.
   Historical context remains opt-in. Report-only explanations can also be reviewed.
2. Under **模型解释**, inspect the source links and historical evidence. For each
   observation, hypothesis or adjustment rationale select **有证据支持**, **证据不支持**,
   **不确定**, or leave **未核验**. Every rated item requires a reason (1–1000 characters).
3. Enter a locally declared reviewer (1–100 characters) and click **保存逐条核验**.
   Partial review is allowed: untouched items remain unreviewed and lower coverage.
4. JSON retains the saved snapshot and judgments; [structured Markdown and offline
   HTML](REPORTS.md) present them with evidence links and saved coverage counts.
   Unsaved edits are separately labeled `claim_review_draft.status = "unsaved"`
   in JSON and shown in their own readable-report section; they are not a persisted
   revision and do not increase saved coverage. Export before discarding a draft.
5. After reopening the same report/rules, expand **当前来源的核验历史** and refresh.
   **载入此核验** restores the saved explanation, proposal bytes and judgments without
   calling a model. It works with `--review-db` even when no model or archive is
   configured. The original current report/rules and accurate synthetic label are
   still required; the source archive is a convenient way to restore them.
6. Edit and save to append a revision. Latest records appear first. If another tab
   saved first, refresh history and load that revision before making a new decision.

A supported adjustment rationale does **not** approve its score change. Explicit
score approval/rejection/defer still uses the separate **人工复核** workflow and its
critical-negative gate. Base scores and `verdict: not_assessed` remain unchanged.
The summary shows review coverage and counts, not model accuracy or malware probability.
A hypothesis marked supported remains a hypothesis with its original verification step.

## Binding and persistence

- `artemis-claim-review/1` stores the exact explanation and optional original
  proposal bytes, model/context/prompt fingerprints, claim text, references,
  verification steps, derived current/historical/mixed scope, cited current evidence,
  historical context, reviewer, time, reasons and separate base score.
- The generation identity is SHA-256 of canonical ASCII JSON (sorted keys, compact
  separators) of `{explanation, suggestion_file_b64}`. It identifies an exact
  snapshot, not a unique model invocation. Identical snapshots share a revision chain;
  a changed response, model/context metadata or proposal starts another chain.
- A separate per-process HMAC key seals the server-issued generation for the HTTP
  round trip. The browser cannot replace text, citations, attribution or proposal
  bytes while reusing the receipt. Receipts are not included in investigation exports.
  They expire on server restart; reopening an integrity-checked stored review issues
  a fresh receipt. An unsaved draft cannot be resumed with an expired receipt.
- Every save re-parses the explicit current bytes and validates report hash, rule hash
  (including absence), and synthetic provenance. The service reconstructs claim text
  and scope; a review request supplies only each claim ID, rating and reason.
- History and reopening match those exact inputs. Restoring an explanation does not
  silently select its historical case for a future model generation. The saved
  historical records remain visible in that explanation. A new generation starts
  with unreviewed fields; it does not inherit the current displayed judgments.
- Reopening checks cited current evidence and the original rule score against the
  current implementation before issuing a new receipt. A parser/scorer change that
  alters them blocks resumption instead of substituting evidence in an old judgment.
- `BEGIN IMMEDIATE`, a unique generation/revision constraint and
  `expected_previous_id` prevent concurrent or stale edits from overwriting decisions.
  New revisions preserve earlier ones, including reversals to unreviewed.
- Review DB schema **2** adds a separate `claim_reviews` table and input lookup index.
  A schema-1 store is upgraded transactionally on the first explicit review write;
  reads and startup do not migrate it. Existing score-review rows remain intact.
  Current code reads both versions. Older code that only supports version 1 cannot
  open the upgraded store; keep a backup before reverting application versions.
  [STORAGE.md](STORAGE.md) documents verified snapshots and restoring both stores
  at new paths, including reopening a saved generation without a model.
- Generation snapshots are bounded to 128 KiB, persisted records to 256 KiB,
  observations/hypotheses to the existing 8+8 limit, and one adjustment rationale.
  History returns the newest 20 matching records. Browser requests cannot choose a
  database path. Existing loopback/origin/token/JSON size controls apply.

Review identities remain self-declared. Database checksums detect accidental changes,
not a malicious local database owner. The receipt is a local application integrity
check, not a portable signature, authenticated human identity or proof of correctness.
Imported investigation exports are not accepted as server-issued generations.

## Verification and remaining limits

Synthetic Python tests cover current/history/mixed support counts, deliberately false
historical attribution, critical adjustment separation, exact-input/receipt binding,
invalid/partial requests, concurrent revisions, corruption, read-only schema-1 history,
transactional migration/rollback, and restore/revise without a configured model.
Chromium CI covers required reasons, unsaved export labels, save, score-review coexistence,
regeneration reset, page reload/source reopen, restoring and revising judgments,
text-only rendering and desktop/mobile layout. The browser uses a simulated Ollama
service, not real model weights.

This is a per-investigation workflow. It does not modify evaluation runs or automatically
convert judgments into an independent evaluation dataset. CLI evaluation rating files
continue to bind to exact completed runs. Real-model support quality, independent expert
labels and analyst time saved still require the acceptance work in ACCEPTANCE.md.
