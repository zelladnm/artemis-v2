# Artemis v3 — Lite foundation (alpha)

This first delivery builds a **zero-dependency, offline-first IOC investigation core** in parallel with v2. It is **not** a complete replacement for v2.

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

AI and sandboxing remain optional **future adapters**, not installation requirements. This alpha makes no claim of malware-verdict accuracy.

## Proposed follow-up milestones

1. Reliability: typed provider response validation, evidence IDs, local cache with TTL, rate limits, provider contract tests.
2. Enrichment: multiple providers, deduplication, citations, analyst review and validated report export.
3. AI (opt-in): local Ollama/remote adapters with strict evidence-only summary constraints.
4. Isolated analysis (opt-in): ingest sandbox reports from separately managed isolation; never execute unknown files by default.
5. Web experience: thin API/UI, Docker, integration checks and one-command demo.

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
is required; model explanations are not yet implemented.
