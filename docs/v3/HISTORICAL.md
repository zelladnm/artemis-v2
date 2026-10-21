# Explicit historical evidence in local explanations

An analyst can select one archived source as context for a local model explanation.
The server verifies the association, selects bounded current/historical evidence
and validates citations against the exact records sent. This is an initial local
retrieval-augmented workflow using exact report-declared sample hashes. It has no
semantic/vector search, autonomous retrieval loop or historical verdict inheritance.

## Workflow

Use the trusted local Ollama setup and cloud-disable configuration in
[SEMANTIC.md](SEMANTIC.md). Enable a separate source archive and review store:

```sh
python -m artemis_v3.workbench --case-db ../artemis-cases.sqlite --review-db ../artemis-reviews.sqlite --ollama-model YOUR_LOCAL_TAG
```

1. Archive a report using **归档来源**. Its original bytes must contain a valid
   `/target/file/sha256`; source archive details are in [ARCHIVE.md](ARCHIVE.md).
2. Import a distinct current report that asserts the same target SHA-256, set its
   synthetic label accurately and investigate it with any current ruleset.
3. Under **本地调查归档**, find the reference and click **用于本次模型解释**. The
   button is available only with a configured model, matching sample hash and
   synthetic provenance, and a different report fingerprint.
4. Inspect the selected source in **模型解释**, then explicitly click
   **本地模型解释**. Selection itself invokes no model. **移除历史对照** returns
   the next request to the single-source flow and clears the displayed explanation.
5. Current citation buttons open the current evidence browser. Historical citations
   expand the exact sent historical record, with its source pointer and full ID.
   Review the source attribution and omitted coverage before drawing conclusions.
6. A generated adjustment can be sent to the existing manual review flow and saved
   explicitly. Export JSON/Markdown to retain the full accepted explanation,
   historical source selection, sent records and context fingerprint.

The server repeats association checks even if the browser button was enabled.
Unknown/stale/corrupt archives, missing or mismatched sample hashes, identical
report bytes and synthetic-label mismatches fail before model invocation. Current
evidence and deterministic rule results remain available. A different ruleset for
the same report does not constitute another historical source.

Both sample hashes are report assertions, not verified sample identities. Reports
can describe different environments, logging coverage and run times. Historical
activity cannot establish that an event occurred in the current run, and absence
from either selected context cannot establish benignness. Rule catalogs, historical
scores and analyst decisions are not placed into historical model context.

## Context and output contract

The total remains **12 KiB / 32 whole evidence records**. Historical mode allocates
up to 8 KiB / 24 current records initially, preserving representatives of all matched
current critical rules. One historical report contributes at most 8 records within
the remaining total byte budget. The builder prioritizes signatures, API calls
and process records and discloses both sources' omissions. It does not truncate
records to fit. Oversized selected/critical current records or no fitting historical
evidence produce an explicit failure before generation. Selecting more than 24
current references in historical mode fails instead of dropping mandatory evidence.

The model receives `artemis-model-context/2` with current `evidence` and a separate
`historical_context` containing the case/report fingerprints, asserted sample hash
and source pointer, synthetic label, coverage warnings and selected records. It
receives the current rule summary; historical rule scores and archive titles are
excluded. The system prompt version is `artemis-semantic/3` for all new requests.

With selected history, accepted results use `artemis-explanation/2`. Observation
references must belong to one supplied source per item. An observation mixing
current and historical references is rejected; cross-source associations belong
in hypotheses with a nonempty verification method. Hypothesis references may cite
either or both supplied sources. Unknown, invented and
omitted references are refused. The output retains the sent historical evidence,
source identities, association kind and coverage counts for later inspection.
Existing top-level supplied/omitted evidence counts continue to describe only the
current report; historical counts live inside `historical_context`.

For historical mode, the server adds `source_attribution_version` set to
`artemis-source-attribution/1` and a `source_scope` on every accepted observation
and hypothesis. Scope is derived from validated exact references: `current`,
`historical` or `mixed`. Mixed scope is allowed only for hypotheses. The model
schema does not accept a `source_scope` field; a model-supplied attribution label
is rejected rather than trusted. The workbench displays the derived scope above
each claim and exports the same labels. Normalization copies the model entries
instead of mutating the provider's output.

These labels identify citation provenance, not the truth or attribution of prose.
For example, a model may incorrectly write “the current run injected code” while
citing only a historical record. That item is labelled `historical`, which exposes
the discrepancy for human review, but the text's factual support is not verified
automatically. This guard cannot prove resistance to source confusion or prompt
injection.

Adjustment references must belong **only to supplied current evidence**. Historical
or mixed-source adjustment citations are rejected. The original report/ruleset
proposal binding and critical negative-adjustment protection still apply. Every
suggestion remains unapplied until a separate human decision. Citation membership
and source labels do not verify that a model's claim follows from its references.

Without selected history, the existing `artemis-explanation/1` single-source
contract is retained without the new scope fields. No archive is loaded or source automatically selected. The
HTTP interface accepts one optional `historical_case_id` on `/api/explain`; it
never accepts a historical file path or browser-supplied historical evidence.
Ordinary analysis, selection, archive opening and review saving do not generate
an explanation. Changing the current report/label or reopening another case clears
the browser's historical selection.

## Validation and remaining evaluation

Synthetic tests cover association/provenance mismatches, unavailable archives,
stale selection, omitted/fabricated references, mixed observation refusal,
server-derived scopes, model label spoofing, misleading prose with valid historical
citations, cross-source adjustment refusal,
context bounds and current critical signals. Loopback HTTP tests verify an explicit
archive selection reaches a synthetic Ollama service while invalid/default flows
do not load historical context. Chromium CI creates two distinct sources for the
same asserted sample, selects history, expands a historical citation, checks mobile
layout and exports a reviewed current proposal with historical provenance.

These tests validate engineering behavior. No real model or real sample was used
to measure cross-report attribution, factual support or investigative benefit.
The current evaluation CLI's bundled replay suite remains single-source; a labelled
multi-source corpus and pinned real-model evaluation are still needed. Reports
and generated prose remain untrusted data and are rendered as text.
