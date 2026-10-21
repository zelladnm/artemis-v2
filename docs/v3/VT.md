# VirusTotal response contract

Live queries remain explicit opt-in and read-only. This adapter does not submit
files or trigger scans. Tests use synthetic responses; no live query was made.

The response must contain a data object of the expected type (`file`, `domain`,
`ip_address`) and an attributes object. The returned identity must match the IOC;
MD5/SHA1 lookups match the corresponding attribute because file IDs are SHA-256.
Malformed or mismatched data becomes a ProviderError, allowing the engine to
return failed/partial while retaining evidence from other providers.

`last_analysis_stats` must contain at least one supported detection category;
all supplied counts must be nonnegative integers (booleans are rejected).
Missing categories display `unknown`, never zero. A response containing explicit
zeroes is accepted but does not imply benignness. Absent statistics are reported
as unavailable. An absent analysis date remains unknown; a supplied date must be
a nonnegative integer UTC epoch timestamp representable through year 9999.

Responses are read with a 2 MiB limit. Duplicate JSON keys, malformed JSON and
nonfinite JSON constants are rejected. Redirects are refused so credential-bearing
requests cannot be forwarded. HTTP 404 means no evidence; authentication errors,
rate limits, server failures, redirects and timeouts become safe diagnostics.
Error messages omit response bodies and exception text. No retries or persistent
cache are implemented in this iteration.

Contract references checked during implementation:

- https://docs.virustotal.com/reference/files
- https://docs.virustotal.com/reference/ip-object
- https://docs.virustotal.com/reference/domains-object

The existing private-indicator guard is coarse filtering, not comprehensive DLP.
