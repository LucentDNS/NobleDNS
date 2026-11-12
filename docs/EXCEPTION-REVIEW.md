# Exception rule review

## Purpose

DNS exception rules (for example, `@@||host.example^`) can override matching blocking rules in compatible clients. They can restore legitimate functionality, but an overly broad or unjustified exception can also weaken filtering. NobleDNS therefore tracks exceptions separately from blocking rules.

This register records the current simple upstream exceptions found in the AdGuard DNS Filter snapshot captured by NobleDNS GitHub Actions build run 406 (2026-11-12). It is an audit baseline, **not an approval record**.

## Current audit result

- Source: AdGuard DNS Filter.
- Snapshot SHA-256: `544a98f0648cbaaff157528f287758ae44f0ad750546133be4a9efb129a5aac1`.
- Snapshot size: 4,663,192 bytes.
- Snapshot path in the CI audit artifact: `sources/adguard_dns.txt`.
- Verification evidence: [GitHub Actions build run 406](https://github.com/LucentDNS/NobleDNS/actions/runs/43218091766), artifact `nobledns-build-audit-406`.
- Original source line numbers: 178918–178928.
- Simple exceptions parsed into the current main subscription: 11.
- Independently reviewed and approved by NobleDNS in this audit: **0**.
- Status of all 11 entries: `pending`.

Compared with the previously registered snapshot (SHA-256 `51b8e02e339093a858c744cd475948ca3e34e87cae31a29c6adb475e15e48205`, lines 178892–178902), the exact text of all 11 registered exception rules is unchanged: no registered rule was added, removed or modified. Their source line numbers moved forward by 26. The current source bytes and fingerprint above were read from the build artifact, not inferred from a search result.

The 11 rules occur together in the upstream snapshot without an adjacent per-rule explanation in that section. This establishes provenance and syntax, but it does not establish why each exception is needed, which block rule it overrides, whether the exception is still necessary, or whether its scope is appropriate.

The pending status does **not** mean a rule is incorrect. It means NobleDNS has not yet recorded sufficient independent evidence to approve or reject it.

## Register

The machine-readable record is [exception-review.csv](../data/exception-review.csv). Each row records the exact rule, source, snapshot fingerprint, original line number and review status. Evidence, rationale, scope assessment, reviewer and review date remain blank until an actual review is completed.

## Required review procedure

For each exception, a maintainer must:

1. Confirm the exact source rule and snapshot fingerprint.
2. Identify the blocking rule(s) it neutralizes in the merged subscription.
3. Establish the functional breakage or compatibility reason using upstream issue evidence, reproducible tests, or other reliable first-hand evidence. A domain name alone is not evidence.
4. Assess exact scope: the exception must not be broadened beyond the minimum hostname needed.
5. Test the relevant hostname and affected service with the target DNS client(s), where feasible.
6. Record a concise rationale, evidence URL or test artifact, scope assessment, reviewer and UTC review date.
7. Choose one decision: `approved`, `rejected`, or `needs-more-evidence`. A decision must never be inferred from upstream presence alone.
8. Set a review date when the evidence may become stale.

A reviewer must not mark a rule approved merely because it appears in an upstream list or because the hostname looks like an advertising, banking, CAPTCHA or telemetry endpoint.

## Change control

- New upstream exceptions must be detected and reviewed before they are allowed to expand the NobleDNS exception set.
- Removed upstream exceptions must be reconciled against this register; do not silently delete the audit record.
- Changes to an exception's exact hostname or syntax are new rules and require a new review.
- Rejected exceptions must not be activated.
- Pending entries must remain visibly pending; do not fill evidence fields with guesses or generic statements.
- Any future build gate must validate this register against the parsed upstream exception set and must fail closed for unreviewed additions. The gate must not silently convert exceptions into blocking rules or alter DNS semantics.

## Important limitation of this register

This initial register documents the existing 11 exceptions and their provenance. It does not yet implement a build-time approval gate and does not change the current subscription. Until the review decisions and gate are completed, the 11 inherited upstream exceptions remain present in the current build. This limitation is intentional and explicit; no rule has been silently removed or newly approved.

## Related evidence

- [Current active exceptions](../dist/allowlist-active.txt)
- [Current build manifest](../dist/manifest.json)
- [Third-party notices](../THIRD-PARTY-NOTICES.md)
- [Quality policy](QUALITY.md)
