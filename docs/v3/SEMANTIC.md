# Opt-in local model explanations

The workbench can ask an installed local Ollama model to summarize source
observations, propose hypotheses with verification steps, and optionally suggest
a score adjustment. The analyst must verify every conclusion. Model output never
overwrites the deterministic base score or saves a review automatically.

## Start and use

Use a trusted local Ollama service with a model already installed. Configure
`OLLAMA_NO_CLOUD=1` in the **Ollama service's environment**, then restart that
service. Setting it only on the Artemis process does not configure Ollama.
See the [official Ollama FAQ](https://docs.ollama.com/faq) and
[chat API](https://docs.ollama.com/api/chat).

```sh
python -m artemis_v3.workbench --ollama-model YOUR_INSTALLED_MODEL_TAG --review-db ../artemis-reviews.sqlite
```

Replace the model placeholder with its exact local name/tag. Artemis neither
downloads a model nor launches Ollama. The endpoint is fixed to `127.0.0.1`;
`--ollama-port` defaults to 11434. `--model-timeout` accepts up to 60 seconds for
the request sequence. Without `--ollama-model`, the offline workbench remains
available and makes no model calls. No GPU or model is required to run its demo.

1. Import a CAPE report and, optionally, a ruleset, or load the synthetic demo.
2. Optionally select 1–32 evidence records in the evidence browser. Click
   **本地模型解释** explicitly. Startup and ordinary investigation do not send
   report content to the model.
3. Inspect the separate source observations and hypotheses, follow their evidence
   links, and check the suggested verification steps and limitations.
4. If a score suggestion exists, **将此建议送人工复核** imports its exact generated
   proposal. This is still unapplied. Enter a reviewer, decision and reason, then
   save explicitly with a configured review database.
5. Export JSON or Markdown to retain the explanation alongside the investigation
   and current review. Saving review history records the proposal and its exact
   fingerprint; it does not archive the entire model response automatically.

## Evidence and output contracts

`ExplanationProvider` separates transport from the evidence contract. The initial
adapter supports local GGUF models exposed by Ollama; other providers are not
configured by the browser. Requests use the official structured JSON schema
format, non-streaming output, no tools and no requested thinking output.

Context is capped at 32 whole records and 12 KiB of serialized data. Automatic
selection prioritizes signatures, API calls and process evidence. Explicit
selection includes only selected records plus a representative source for each
matched critical rule. If mandatory/selected records exceed the budget, the call
fails before sending evidence rather than truncating them. The model also sees
the report fingerprint, synthetic status, rule summary and up to eight coverage
warnings. Exports disclose supplied evidence IDs, total/omitted counts and the
selection mode. The byte budget is not a guarantee about a model's tokenization.

The `artemis-explanation/1` result contains source observations, hypotheses with
verification steps, limitations and an optional evidence-bound proposal. Unknown
fields, malformed JSON, duplicate keys, tool calls, incomplete responses and
references outside the supplied context are rejected. Citation membership checks
do **not** establish that the text follows from the cited evidence. Instructions
embedded in reports are treated as untrusted data in the prompt; the model is
given no execution or tool interface.

Proposals reuse `artemis-proposal/1` validation against the exact report and ruleset.
Critical negative adjustments remain blocked. Base score, proposed adjustment
and the separately approved analyst score retain their existing meanings.
Explanations record model identity/artifact digest, metadata/response/context
hashes and prompt version `artemis-semantic/1`. These aid traceability, not
authentication or guaranteed reproducibility.

## Transport and failure behavior

Before sending evidence, Artemis queries `/api/tags` and `/api/show` using only
the model name. Missing models, cloud metadata, unsupported formats and missing
artifact metadata are rejected. Transport bypasses proxies, refuses redirects,
bounds HTTP responses to 1 MiB and explanation content to 128 KiB, and permits
one in-flight generation per server provider. Unavailable, timed-out or invalid
model responses leave original evidence and rules available for manual work.

A loopback address alone cannot establish that a model runs locally. Disable
Ollama cloud support as above and keep the service trusted. Metadata checks are
not isolation from a malicious local service or an alias changed during a call.
This feature does not execute samples, start a sandbox or contact a remote model.

## Validation and remaining work

```sh
python -m unittest discover -s tests -p 'test_v3*.py' -v
```

The suite includes a real loopback HTTP fixture implementing the Ollama protocol,
schema/citation/context failures, cloud preflight refusal and explicit workbench
review. CI runs the existing Chromium desktop/mobile flow plus a model explanation
and rejected-proposal/export flow using that synthetic fixture. The fixture is
test-only and is not exposed as a production model option.

No real model weights or real malware reports were used to validate this delivery.
Model-specific compatibility, latency, explanation quality and factual support
remain unmeasured. Next: build an independently labelled, sanitized evaluation
set and run a pinned local model with report/model/rules/prompt fingerprints,
checking citation support and dangerous downscoring as well as schema success.
