# Evidence-backed regression corpus

The canonical corpus is `tests/fixtures/evidence-corpus.json`. It is intentionally empty until real records meet the evidence standard. Do not seed it with unverified upstream candidates or synthetic hostnames.

## Record schema (version 1)

The JSON document has exactly two top-level keys:

- `schema_version`: integer `1`.
- `records`: array of unique-hostname records.

Every record must contain exactly these required fields (plus optional `expires_at_utc`):

| Field | Requirement |
|---|---|
| `hostname` | Lowercase FQDN, validated by the same `valid_domain()` function used by the production builder |
| `classification` | `confirmed_ad`, `confirmed_tracker`, `unwanted_telemetry`, `threat`, `essential_service`, or `unresolved` |
| `evidence_type` | `controlled_traffic_capture`, `vendor_documentation`, `independent_research`, `threat_intelligence`, `upstream_rule`, `user_report`, or `synthetic_test` |
| `evidence_reference` | HTTPS URL without embedded credentials or query parameters, or a safe repository-relative path under `docs/`, `tests/`, or `audit-artifacts/` |
| `observed_at_utc` | ISO-8601 UTC timestamp ending in `Z` |
| `reviewed_at_utc` | ISO-8601 UTC timestamp ending in `Z`, not earlier than observation |
| `review_due_utc` | ISO-8601 UTC timestamp ending in `Z`, not earlier than review |
| `confidence` | `high`, `medium`, or `low` |
| `service` | Product, service, or controlled test name |
| `affected_function` | Specific observed function, not a vague category |
| `source_rule_refs` | Array of source/rule references; empty when not derived from a source rule |
| `source_snapshot_sha256` | Array of lowercase 64-character SHA-256 hashes; required when source rule references are present |
| `expected_policy` | `blocked`, `allowed`, or `observe_only` |
| `review_notes` | Non-empty rationale and limitations |

Optional `expires_at_utc` is an ISO-8601 UTC timestamp. It is mandatory for threat indicators.

## Safety invariants

- A hostname appears only once. Conflicting functions or evidence must be reconciled into one reviewed record rather than silently duplicating the host.
- `unresolved` records must use `observe_only`; they cannot become pass/fail blocklist sentinels.
- `confirmed_ad`, `confirmed_tracker`, and `unwanted_telemetry` require high-confidence controlled traffic capture, vendor documentation, or independent research. An upstream list match, user report, or synthetic test is not sufficient to establish a confirmed classification.
- `threat` requires high-confidence `threat_intelligence`, an expiry timestamp, and revalidation before expiry.
- `essential_service` records must expect `allowed` and require high-confidence controlled traffic capture, vendor documentation, or independent research.
- `schema_version` must be the integer `1`; booleans and floating-point values are rejected even if Python would compare them equal to `1`.
- Tracking and telemetry are distinct from advertising and must not be reclassified as ads without evidence.
- Observation and review timestamps cannot be in the future. Overdue reviews and expired evidence fail validation; re-review and update the evidence dates before reuse.
- Evidence references must be traceable and safe: insecure HTTP, embedded credentials, query parameters, absolute paths and parent-directory traversal are rejected.
- Unknown or missing fields fail closed. No private account identifiers, device identifiers, authentication tokens, or unsanitized personal traffic logs may be committed.

## Validation

The validator uses only Python standard library plus NobleDNS's existing production domain validator:

```powershell
python -m unittest discover -s tests -v
python tools/validate_evidence_corpus.py
```

Tests use synthetic data in memory and do not add fake domains to the public corpus. The corpus is not consumed by the production rule builder and cannot add or remove subscription rules.

A valid corpus is not proof that a rule is safe to block. Human review and controlled client compatibility testing remain separate acceptance requirements.
