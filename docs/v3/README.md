# Artemis v3 — Lite foundation (alpha)

This first delivery builds a **zero-dependency, offline-first IOC investigation core** in parallel with v2. It is **not** a complete replacement for v2.

The current development chain includes the workbench, local model adapter,
review/history, source archive and explicit historical context described below.
The integrated acceptance branch also incorporates the previously separate VT
response fix. See [the current acceptance checklist](ACCEPTANCE.md) for reproducible
commands, completed engineering scope and remaining real-data/model validation.
The [offline evaluation review mode](EVALUATION_REVIEW.md) lets analysts open fixed
outputs, inspect their evidence, save judgments and export exact-run human ratings
without editing each JSON claim or invoking a model again.
Draft branches have not been merged into main or released.
The [local suite preparation commands](PREPARATION.md) copy selected reports into
a fingerprinted draft and preflight its production context without a model;
analysts still supply independent rule expectations and reference notes.

## Quick start (Python 3.11+)

No Ollama, VM, GPU, ChromaDB, secrets, or network access required. From the repository root:

    python -m artemis_v3 demo.example
    python -m artemis_v3 203.0.113.10 --format json
    python -m unittest discover -s tests -p 'test_v3*.py' -v

The indicators demo.example, 203.0.113.10 and a hash of 64 a characters are **synthetic fixtures**. Results are explicitly marked as demo data, not real threat intelligence. Other inputs return no_evidence, never a clean verdict.

## Optional read-only live IOC lookup

Set VT_API_KEY in your shell environment (do not check it into Git), then run:

    python -m artemis_v3 8.8.8.8 --source virustotal --format json

Live lookup is **opt-in** and submits the entered indicator to VirusTotal. Do not send confidential or internal indicators or sensitive customer information. The implementation blocks private/reserved IPs and some local/example domains, but this is **not comprehensive DLP**. Raw samples are never uploaded or executed. Missing provider data does not imply safety.

## Architecture

- indicators.py: parsing, normalization, coarse external-query guard.
- models.py: evidence object, structured result, provenance and demo labelling.
- providers.py: provider interface, synthetic demo, optional read-only VirusTotal.
- engine.py: stateless investigation with explicit partial failures.
- cli.py: command-line interface with JSON and Markdown output.
- tests/test_v3.py: network-free regression tests.

AI is available through an opt-in local workbench adapter; sandboxing remains a
future adapter. Neither is an installation requirement. This alpha makes no
claim of malware-verdict accuracy.

## Proposed follow-up milestones

1. Validate deployed CAPE report variants with sanitized source contracts.
2. Measure pinned real local models, factual support, dangerous adjustments and analyst time saved.
3. Review the integrated draft code and test deployment/backup/recovery on target systems.
4. Rebuild isolated Worker task management and richer forensic evidence as a separate optional mode.
5. Expand production rules, independent evaluation data and evidence-bound retrieval.

## Compatibility

Legacy Gradio v2 code is not changed in this first alpha. Do not use this preview on production cases.

## Recovery and behavior evidence

See [the recovery inventory](RECOVERY.md) for the thesis-to-code comparison and revised priorities.
[Offline CAPE import](CAPE.md) is now available as a bounded, read-only evidence adapter.
It does not require a sandbox or execute samples.

## Local investigation workbench

Run `python -m artemis_v3.workbench` and open the printed loopback address. Load the
synthetic demo to inspect process relationships, timelines and source evidence.
[Workbench documentation](WORKBENCH.md) covers optional rule/suggestion imports,
explicit local analyst review persistence and report exports. No model or sandbox
is required. [Local model explanations](SEMANTIC.md) can be enabled explicitly;
they retain evidence references and send any adjustment through analyst review.

[Semantic evaluation](EVALUATION.md) runs fixed suites with synthetic replay or an
explicit pinned local model, records failures and produces human support-review
templates. Technical acceptance is kept separate from explanation quality.

[Local source archival](ARCHIVE.md) adds opt-in report/ruleset persistence, exact
report or report-declared sample SHA-256 lookup and reopening in the workbench.
[Historical context](HISTORICAL.md) lets an analyst explicitly select a matching
archived source for cited model explanations while keeping score proposals bound
to current evidence.
