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
- All 11 are explicitly marked `baseline_active=true`: this freezes the inherited behavior temporarily; it is not an approval decision.

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

- The build compares each source's parsed exception set with this register and fails closed on any unregistered addition or unreconciled removal.
- New upstream exceptions must be added to the register with complete provenance and evidence, then independently approved before activation. A new `pending` entry cannot pass the build.
- Removed upstream exceptions must be reconciled and marked `retired` with reviewer, date, rationale, evidence and scope assessment; do not silently delete the audit record.
- Changes to an exception's exact hostname or syntax are new rules and require a new review.
- Rejected exceptions must not be activated.
- The 11 frozen legacy entries may remain active only while they remain in the hard-coded baseline and are explicitly marked `pending` with `baseline_active=true`. This is a temporary compatibility hold, not an approval.
- Pending entries must remain visibly pending; do not fill evidence fields with guesses or generic statements.
- Rejected and `needs-more-evidence` entries remain in the audit register but are not emitted as active exceptions. The gate must not silently convert exceptions into blocking rules or alter DNS semantics.

## Build-time enforcement and remaining limitation

The build now validates the exact parsed upstream exception set against this register. Unregistered additions, unreconciled removals, invalid states and new pending entries fail the build. Approved entries are emitted; rejected and `needs-more-evidence` entries are retained for audit but not emitted. The 11 inherited entries are temporarily grandfathered as an exact, code-pinned pending baseline so the gate does not silently change existing filtering behavior. They are still **not approved**. This is a containment measure, not a substitute for the required per-rule evidence review. The three entries with observed overlap against the current compiled block rules deserve priority. The 10010 exception is the parent of a more specific blocked subtree (`m1.ad.10010.com`) and therefore has the broader exception scope. The two TVB exceptions are narrower child-host exceptions (`api.ads.tvb.com` and `img.ads.tvb.com`) beneath the blocked parent `ads.tvb.com`; they do not allow the entire parent domain. See [Active exception overlap audit](EXCEPTION-OVERLAP-AUDIT.md) for the reproducible snapshot and exact findings.

## Related evidence

- [Current active exceptions](../dist/allowlist-active.txt)
- [Current build manifest](../dist/manifest.json)
- [Third-party notices](../THIRD-PARTY-NOTICES.md)
- [Quality policy](QUALITY.md)
