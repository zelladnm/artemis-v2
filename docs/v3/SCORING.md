# Artemis v3 — Auditable signature scoring scaffold

This is an **offline research scaffold**, not a malware verdict engine and not a reconstruction of the thesis's original scoring weights. It consumes the normalized evidence produced by the existing CAPE JSON adapter.

## What is implemented

- Analyst-defined, versioned exact signature-name rules. No default production rules or invented MITRE ATT&CK mappings.
- Each matched rule is counted once, with the originating evidence IDs preserved for independent review.
- Rule points are capped at 10. Zero means **no configured rule matched**, not a benign sample or calibrated probability.
- Report coverage warnings and synthetic-fixture labels remain attached to the assessment.
- A semantic adjustment can be **proposed**, but never applied automatically. It must cite evidence IDs from the same source report and provide a rationale.
- A negative proposal in the presence of a configured critical signal is blocked; all other proposals require analyst review.

## Local, synthetic example

    from artemis_v3.cape import load_cape_report
    from artemis_v3.scoring import SignatureRule, assess_signatures
    report = load_cape_report("tests/fixtures/cape_synthetic.json", synthetic=True)
    rules = [SignatureRule("DEMO-1", "synthetic_behavior", 1)]
    result = assess_signatures(report, rules, version="synthetic-demo/1")
    print(result.as_dict())

Run regression tests:

    python -m unittest discover -s tests -p 'test_v3*.py' -v

The example rule is intentionally synthetic; it is **not** a real threat detection. No sample execution, external API call, model inference, automated remediation or persistence is performed.

## Remaining work

- Define and peer-review actual rule catalogs with documented evidence semantics.
- Validate against independently labelled, authorized benign and malicious report datasets.
- Measure false positives, false negatives, rule coverage and harmful downgrade proposals.
- Implement explicit analyst approval records and optional evidence-constrained LLM review.
- Restore dynamic analysis capabilities only through separately reviewed isolation services.

The original thesis experiments and scoring weights are historical design references, not evidence that this scaffold is accurate.

## CAPE v2 evidence and CLI integration

The scaffold is now tested with `cape-evidence/2`. It scores exact **signature**
names only: API calls, failed return values and installer filenames are retained
as evidence but do not silently become scoring rules. This is still a research
scaffold; it does not restore the thesis's complete Hybrid Threat Scoring algorithm.

Use a deliberately selected local ruleset (no built-in production rules):

```sh
python -m artemis_v3 --cape-report tests/fixtures/cape_synthetic.json --synthetic --ruleset tests/fixtures/scoring_synthetic.json --format json
```

The committed ruleset is **synthetic demo data**, not a detection catalog. Its JSON
requires `version`, `synthetic` (boolean), and `rules` (1–128 entries). Each rule has
`rule_id`, exact `signature_name`, integer `points` (1–10), and optional boolean
`critical`. Duplicate IDs/signature names, unsupported fields and invalid types are
rejected. Input is limited to 64 KiB and duplicate JSON keys are rejected. A digest
identifies exact catalog bytes, not their trustworthiness. Rules must be reviewed
by the analyst; report contents and model output never auto-load catalogs.

With `--ruleset`, output uses `artemis-assessment/1` and contains the original
normalized `report` (including timeline), `rule_assessment`, `ruleset_sha256`, and
`ruleset_synthetic`. Without it, existing report output remains unchanged. Source
and catalog synthetic labels are separate and visible; missing coverage warnings
carry into the assessment. Zero points mean no configured signature matched.

Adjustment proposals remain a Python API, not automated AI output. They cannot
apply a changed score. Critical findings block negative proposals, and other
proposals await review. Arguments are trusted in-process objects, not authenticated
review records or an authorization boundary; persistence, explicit analyst identity,
rule authenticity and a review application workflow are future work.

This integration reuses the original scoring implementation from commit
`4c31634` and adds configuration validation and offline CLI/compatibility tests.

## Analyst decisions

[Local review history](REVIEW.md) now provides explicit approve/reject/defer records
bound to report and catalog fingerprints. The deterministic score remains intact;
a separately recorded analyst score requires approval. This adds local persistence
and stale-write protection. Authenticated identity, enterprise authorization and a
multi-party approval workflow are still future work.
