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
