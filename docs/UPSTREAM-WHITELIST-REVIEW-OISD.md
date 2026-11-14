# OISD whitelist review

**Reviewed:** 2026-11-14  
**Decision:** Do not import any OISD included whitelist wholesale into NobleDNS.

OISD states that the listed whitelists are already applied to OISD Small/Big and do not need to be added manually by OISD users. This describes OISD's own list construction; it is not a recommendation to apply the same allow rules to independent DNS blocklists.

## Findings

| Source family | Relevance to NobleDNS | Decision |
|---|---|---|
| AdGuard DNS exclusions | Useful evidence for investigating individual false positives and service-compatibility exceptions. The list is issue-linked and contains many context-specific entries. | Use as a review corpus only. Compare candidates against current NobleDNS blocking rules and require a reproducible impact or upstream rationale before adding any exception. |
| AdGuard HTTPS exclusions (Android, Windows, macOS, Firefox, banks, sensitive, issues) | Some entries concern platform-specific HTTPS filtering behavior rather than DNS blocking. | Do not import as DNS exceptions. Inspect an individual entry only when a matching compatibility report exists. |
| China CDN domain whitelist | Covers broad shared infrastructure and multiple CDN providers. Parent-domain allowances could exempt unrelated customer traffic and weaken blocking well beyond the intended service. | Do not import. Consider only narrowly scoped, evidence-backed host exceptions. |
| HaGeZi URL-shortener and referral whitelists | Primarily address URL/filtering behavior and referral handling; they are not a general-purpose DNS compatibility allowlist. | Not applicable as a bulk DNS exception source. |
| General, optional, referral, and commonly-whitelisted domain lists | Broad or context-dependent allow recommendations without a sufficiently narrow NobleDNS-specific justification. | Do not import. |

## Policy

1. Never copy an upstream whitelist wholesale into the production exception set.
2. Treat upstream exclusions as leads, not approvals.
3. Require an exact hostname, the blocking rule that matches it, a reproducible affected function or authoritative upstream rationale, and a scope assessment.
4. Prefer the narrowest possible exception. Avoid parent-domain allowances for shared services and CDNs.
5. Run rule-interaction and client regression checks before changing production exceptions.
6. Keep inherited exceptions marked as pending until independently reviewed; do not treat upstream inclusion as NobleDNS approval.

## Sources

- [OISD included whitelists](https://oisd.nl/includedlists/whitelists)
- [AdGuard DNS filter exclusions](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt)
- [China CDN domain whitelist](https://raw.githubusercontent.com/mawenjian/china-cdn-domain-whitelist/master/china-cdn-domain-whitelist.txt)
- [HaGeZi URL-shortener whitelist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt)
- [HaGeZi referral whitelist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt)

This review records source suitability and import policy. It does not approve, add, remove, or alter any production exception.
