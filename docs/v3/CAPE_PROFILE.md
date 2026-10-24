# Local CAPE compatibility profile

For P0 format acceptance, analysts can generate a **read-only, content-free
structural profile** of an explicitly selected CAPE `report.json` without
sending its original report, paths, commands, network indicators, sample hash,
or evidence IDs to stdout.

```sh
python -m artemis_v3.cape_audit --report /private/report.json \
  --cape-version 'operator-declared CAPEv2 version' > /private/profile.json
```

The version is an **operator declaration**, not a value authenticated by the
report. A successful exit (`0`) means only that the existing bounded CAPE
parser accepted the selected subset. Exit `2` means a report was not accepted;
error output deliberately excludes the input path and raw parser diagnostic.

Output (`cape-compatibility-profile/1`) includes parser schema, `parsed`/`partial`
status, counts by evidence category, parent links and timeline clock domain,
13 summary-field `absent`/`empty`/`reported` states with record counts, and a
warning count. It intentionally excludes source strings, hashes, pointers,
model explanations and original report bytes. The profile does **not**
anonymize metadata: even field presence and counts can reveal operational
information. Review before sharing outside the investigation environment.

Use this profile to compare deployed CAPE/processor versions, identify sparse
or unsupported structures and plan private field-level acceptance checks. It
cannot verify source authenticity, behavior success, sample identity, malware
classification or actual deployment compatibility. The original bytes must
remain local for evidence verification. No model, sandbox, network, subprocess,
file from the report, or external package is required.

Tests use synthetic data only:

```sh
python -m unittest discover -s tests -p test_v3_cape_audit.py -v
```
