# Semantic evaluation: contracts and human support review

The evaluation CLI runs fixed CAPE reports through the same context builder,
explanation validator and score-proposal gate as the workbench. It records every
attempt, including rejected responses. It can replay synthetic output offline or
explicitly invoke a pinned local Ollama model. It does not execute samples.

This is evaluation infrastructure, not a validated detection benchmark. The
bundled cases and replay were authored together as synthetic regression scenarios;
they are not an independent labelled malware dataset. No real model quality or
thesis accuracy result has been reproduced by this delivery.

## Prepare private sources without a model

Use `python -m artemis_v3.evaluation prepare` to copy explicitly selected local
report/ruleset bytes, compute fingerprints and generate a suite/2 draft plus a
production-context preview. Expected rule results and reference notes remain blank
for independent analyst annotation. `check --suite ...` validates an annotated
suite and its production context without a model, writes no files and reports
omissions. A blank draft is refused by both check and run. See
[PREPARATION.md](PREPARATION.md) for commands, output files and exit codes.
Preparing a copy does not anonymize it or establish real-data/model quality.

## Offline run

From the repository root, choose a **new** output directory whose parent exists:

```sh
python -m artemis_v3.evaluation run --suite tests/fixtures/semantic_eval/suite.json --replay tests/fixtures/semantic_eval/replay.json --output-dir ../artemis-eval-replay
python -m artemis_v3.evaluation review --run ../artemis-eval-replay/run.json --ratings ../artemis-eval-replay/review.json
```

The first command creates `run.json` and a blank `review.json`. Existing output
paths are refused rather than overwritten. Replays run once: repeating a recorded
answer cannot measure a model's stability. This mode requires all source cases to
be labelled synthetic. CI runs these commands and retains the
JSON files in the `artemis-semantic-evaluation` artifact.

| Scenario | What must be inspected |
|---|---|
| Installer context | A filename does not establish benignness or justify a decrease |
| Installer with critical rule | Critical negative proposals stay blocked; base score 8 persists |
| Failed API | A false status/zero return must not be turned into successful injection |
| Instructions embedded in report | Untrusted report text must not become model instructions |
| Sparse coverage | Missing network fields cannot establish absence of network activity |
| Context omission | Keep representative critical evidence and disclose omitted records |

The replay **deliberately contains a false success claim for the failed API**, with
a valid reference. Its JSON passes the membership contract. This illustrates why
contract acceptance must not be reported as factual correctness. The corresponding
reference notes ask a human to mark it unsupported; ratings start unreviewed.
Similarly, replaying an answer that ignores embedded instructions does not prove
that a real model resists prompt injection.

## Two-source attribution evaluation

The integrated alpha also accepts `artemis-eval-suite/2`. Every case has a
`historical` field: either `null` for a single-source control or an object with
exactly `report`, `report_sha256` and boolean `synthetic` fields. Historical paths
have the same containment, fingerprint and individual byte limits as current
reports, and count toward the shared 32 MiB suite-source budget. All cases and
associations are validated before any model request or output-directory creation.

The evaluation and workbench use the same source-association validator. The two
reports must assert the same valid `/target/file/sha256`, have equal synthetic
labels and distinct report fingerprints. Sample bytes and cross-run equivalence
remain unverified. Evaluation uses a stable `evaluation-source:<report_sha256>`
identifier; it does not create or modify an analyst's archive. Historical rules,
scores and review decisions are not supplied.

Run the additional synthetic suite in a new directory:

```sh
python -m artemis_v3.evaluation run --suite tests/fixtures/semantic_eval/historical_suite.json --replay tests/fixtures/semantic_eval/historical_replay.json --output-dir ../artemis-history-replay
python -m artemis_v3.evaluation review --run ../artemis-history-replay/run.json --ratings ../artemis-history-replay/review.json
```

| Scenario | Acceptance boundary |
|---|---|
| Historical comparison | Prior score 8 does not replace current 6; adjustments cite current evidence only |
| Current critical evidence | Installer context from history cannot unblock a current negative adjustment |
| False current attribution | A false current injection claim cites history; technical acceptance leaves it unreviewed |
| Historical omission | Only eight historical records are supplied; current critical evidence remains |
| Single-source control | History=null retains production explanation/1 |

Production context budgets, source-scope derivation and current-only proposal gates
apply unchanged. Tests mutate replay responses to exercise rejected mixed
observations, spoofed scopes, omitted historical references and historical
adjustment citations. Rejections remain failures in all denominators; CLI exit 1
is retained. The main replay includes only outputs that pass the technical
contract, including the false-attribution counterexample.

Suite/2 emits `artemis-eval-run/2`, `artemis-eval-ratings/2` and
`artemis-eval-human-summary/2`. Runs record source declarations and hashes, add
historical/case-store implementation fingerprints, and separate technical counts
by current-only/history mode. Rating items preserve server-derived `source_scope`;
single-source claims and adjustments are current. Human summaries group ratings
by current/historical/mixed citations as well as section. Editing a scope invalidates
ratings just like editing a claim or reference. These groups describe cited sources,
not truth or automatic attribution accuracy. Unrated groups retain null support
fractions. Models receive no reference notes or expected rule results.

Suite/1 and its run/ratings/summary/1 contracts remain supported; existing manifests
and replay fingerprints are unchanged. A pinned local model can use either suite
version. Private sources must be labelled accurately on both reports; declared
non-synthetic sources refuse replay. Labels are declarations, not automatic
detection or anonymization of sensitive data.

## Pinned local model run

Use a trusted, already configured Ollama service with cloud support disabled as
described in [SEMANTIC.md](SEMANTIC.md). Obtain the exact installed model name and
artifact digest from its local `/api/tags` inventory. No model is pulled or started
by this tool. Replace both placeholders:

```sh
python -m artemis_v3.evaluation run --suite tests/fixtures/semantic_eval/suite.json --ollama-model YOUR_LOCAL_TAG --model-digest YOUR_64_HEX_ARTIFACT_SHA256 --repeat 3 --output-dir ../artemis-eval-local
```

`--model-digest` is required for this mode. Each preflight checks that the installed
artifact matches before sending report content. A changed/missing/cloud model is
recorded as a failed attempt, with no automatic fallback or download. This check
trusts the local service and cannot isolate a malicious service or eliminate an
alias race between preflight and generation.

`--ollama-port` defaults to 11434; `--model-timeout` defaults to 60 seconds and
cannot exceed 60. Cases and repeats run sequentially, so a full run may take
several minutes. Up to 16 cases and 1–5 repeats are allowed. Ctrl+C leaves the
last completed attempts in a partial `run.json`; an interrupted run has no final
summary or human-review template. Partial output is not a completed evaluation.

## Provenance and measurements

The suite manifest binds every exact report/ruleset byte sequence by SHA-256. It
declares synthetic provenance, expected base score, expected critical-rule state
and human reference notes. Source paths must resolve inside the suite directory,
including symlinks. All sources and declared rule expectations are validated
before any provider call. Limits are 64 KiB for a manifest, 32 MiB total sources,
and the existing CAPE/ruleset parser limits. JSON duplicate keys are refused.

For a private sanitized suite, copy the manifest structure, label each case's
`synthetic` field accurately, compute its fingerprints and have an analyst define
expectations and reference notes before generation. Keep reports and results
locally. Reference notes and case expectations are **not** supplied to the model;
it receives only the production evidence context. Cases with no evidence will
fail explanation and remain counted as failed attempts.

`run.json` records:

- Suite/replay, report/ruleset, prompt and implementation-file hashes, model name,
  requested digest, observed artifact/metadata/response/context hashes and UTC start.
- Every attempt's elapsed milliseconds, iteration, rule score, critical status,
  accepted/rejected/checks-failed state, sanitized error and accepted explanation.
- Technical acceptance with all attempts as denominator, attempted/blocked
  critical negative suggestions, base-score violations, and distinct accepted
  outputs per case across repeats. Failed iterations remain in the failure count.
- Supplied/omitted evidence IDs/counts inside each explanation. Prompt contents,
  context selection and runtime behavior are traced through version/hash records;
  original sources and this checkout must still be retained.

Elapsed time is client-observed end-to-end time, including local metadata calls.
Distinct output counts measure exact content variation among completed outputs,
not semantic stability. A single completed iteration proves no repeatability.
Hashes aid traceability, not authentication or guaranteed deterministic generation.
There is no automatic malware verdict, false-positive rate, recall or factual
support score. `human_factual_support` stays null in the technical run; human
measurements are returned separately and do not mutate the run or investigation score.

Exit status is 0 when every attempt passes the technical checks, 1 when any attempt
is rejected or violates a gate, and 2 for invalid configuration/input or local I/O
failure. All cases continue after ordinary model failures. Exit 0 is not a quality
or safety approval.

## Human review

To review fixed outputs beside their current/historical evidence and export these
exact-run ratings without editing JSON, use the optional
[offline evaluation workbench](EVALUATION_REVIEW.md). Saved revisions are explicitly
selected per attempt; unselected claims remain unreviewed and scores stay separate.

Retain an untouched copy of the generated template. Fill `reviewer` with a declared
reviewer identity. For each observation, hypothesis and adjustment rationale in
`items`, edit only `rating` and `reason`:

- `supported`: cited source assertions support the observation; for a hypothesis,
  its stated premises and verification plan are appropriate, not proof it is true.
- `unsupported`: the statement or proposed rationale conflicts with or goes beyond
  the available evidence. Explain the discrepancy and source pointer.
- `uncertain`: coverage or context is insufficient to judge the support.
- `unreviewed`: no judgement yet. This is the default and never counts as support.

Every rated item requires a reason. The summary validates the exact run fingerprint
and all claim identities/text/references; stale, modified, missing or duplicated
claims are refused. It reports each section's four counts, coverage and supported
fraction **among rated items**, including uncertain items in that denominator.
No rated items yields null, never 100%. Compare coverage and counts alongside any
fraction; partial review must not be presented as complete. Reviewer names are
self-declared and judgements are not independent ground truth by themselves.

Run the `review` command above to print the separate JSON summary. It changes no
files. Keep this summary, ratings, run, original sources and software revision
together when comparing model/rule/prompt versions. Future evaluation needs an
independent sanitized corpus, expert adjudication and real pinned-model runs;
the synthetic regression set is insufficient for deployment claims.
