# Readable investigation reports

The workbench exports a structured Markdown report and a standalone HTML report
from the current investigation. They organize rule results, model claims, saved
human judgments and source references for handoff. No model is called and no
review or archive is written during export.

## Use

1. Open a report and optional rules in the [workbench](WORKBENCH.md).
2. Optionally generate an explanation, [save per-claim judgments](CLAIM_REVIEW.md)
   and record an independent score decision. Without a model, source and rule
   reporting still works; missing rules or judgments remain explicitly missing.
3. Click **导出 Markdown** for a structured text report, or **导出 HTML** for offline
   reading in a browser. HTML includes internal evidence links and print styles;
   use the browser's print dialog to print or save as PDF. Markdown evidence links
   use GitHub-style heading fragments (`#c01`, `#e001`); other viewers may differ.
4. Keep **导出 JSON** alongside the readable report when the complete normalized
   evidence, timeline and warnings are needed. Preserve the original report and
   rules separately, or use the explicit source archive.

The files contain investigation content without automatic anonymization. Share
them according to the sensitivity of the source. They do not contain the local
generation receipt. HTML needs no service, scripts, fonts or external assets to
read; it does not follow source URLs. Source strings, reviewer text and model
output remain literal text, including strings resembling HTML or Markdown links.

## What the report preserves

- Exact report and rule fingerprints, separate synthetic labels, and the target
  sample hash **declared by the report**, which has not been verified against a file.
- Rule findings and their representative evidence, unchanged base score, imported
  proposal if selected, critical-negative gate, and selected saved score decision.
  An approved analyst score is separate from the base score, including a valid zero.
- Model/weights/prompt/context/response/generation fingerprints, current and
  historical context coverage, observations, hypotheses with verification steps,
  adjustment rationale and model limitations.
- Current/historical/mixed citation scope, saved support judgments and reasons,
  reviewer declaration, revision ID and coverage. A selected revision is not
  presented as the latest record in the database.
- Unsaved form edits in a separate draft section, including incomplete reasons or
  reviewer fields. They never increase saved coverage or approve a score change.
- Pending unsupported, uncertain or unreviewed claims; parsing warnings; separate
  clock-domain timelines; numbered evidence excerpts with original JSON pointers.

The report always states that a final malware conclusion has not been recorded.
Rule scores are not probabilities. Valid citation membership does not establish
that a claim is true, and a supported hypothesis remains a hypothesis. Human
support ratings and score decisions remain independent.

## Bounds and full-data export

Readable reports show at most 100 warnings, 20 timeline events per clock domain
and 256 selected evidence excerpts. References are prioritized by model claims,
score proposals/decisions, one representative for each rule finding, then timeline
events. Counts disclose omissions. A reference without an excerpt is shown as its
ID with a JSON-export notice, not a broken internal link.

Each displayed value or evidence JSON block is limited to 4,000 characters with
an explicit truncation marker. Control, bidi and surrogate characters are made
visible. A completed report may not exceed 8 MiB; oversized exports fail with a
message to use JSON. The source objects are not shortened or modified. JSON retains
all normalized records but is not a substitute for original report/rule bytes.

## Export binding

`POST /api/export` uses the same explicit input bytes and loopback/origin/token/size
controls as analysis. Its `export_request` has exactly these fields:

```json
{
  "format": "html",
  "generation": null,
  "receipt": null,
  "claim_review_id": null,
  "claim_draft": null,
  "score_review_id": null
}
```

`format` is `html` or `markdown`. A model report supplies the server-issued
`generation` (`explanation` plus `suggestion_file_b64`) and its receipt. Source and
rule bindings are checked again. Saved reviews are selected by ID from the explicit
startup review store; browser-supplied review bodies are not accepted. The service
checks the exact generation, cited current evidence, rule assessment and score
proposal against the current implementation. A draft must match the generation and
be based on the selected saved claim-review ID, or both IDs must be absent.

The response contains `filename`, `mime_type` and `content`. There is no automatic
download or write on analysis, and the request cannot choose a filesystem path.
Export works without stores when no saved records are selected. Reading records
does not migrate the review database.

Generation receipts expire after a server restart. Reopen the exact original
sources and a saved claim review to obtain a new receipt without calling a model.
An unsaved generation cannot be authenticated after restart; a JSON export can
preserve the browser's existing draft, but it cannot be imported as a trusted
generation. Checksums and receipts are not authenticated analyst identities,
portable signatures or evidence of factual correctness.

## Verification

Synthetic Python tests cover source/receipt/revision binding, read-only operation,
separate draft counts, historical attribution, score preservation, valid zero,
critical downgrades, literal hostile text, internal links, display bounds and HTTP
export without additional model calls. Chromium CI opens the downloaded HTML as a
standalone file, checks desktop/mobile layout and links, rejects external requests,
and saves print PDFs and screenshots for inspection. Real models, real CAPE
contracts, analyst handoff quality and time saved remain acceptance work.
