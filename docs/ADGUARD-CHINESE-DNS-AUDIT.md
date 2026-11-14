# AdGuard Chinese filter: DNS-scope audit

> Status: audit-only. AdGuard Chinese is **not** a NobleDNS production source.

## Decision

Do not add AdGuard Chinese wholesale and do not add EasyList China as a second regional source. AdGuard documents its Chinese filter as originally based on EasyList China and subsequently maintained through its own user feedback and changes. The two are therefore not independent coverage layers that should simply be stacked.

AdGuard Chinese is primarily a browser/content filter. NobleDNS is a hostname-level DNS list. Only narrowly selected hostnames with independent evidence of unwanted DNS behavior could ever be considered for NobleDNS; this audit does not approve any rule.

## Snapshot inspected

- Upstream file: [AdGuard Chinese filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt)
- Repository: [AdguardTeam/FiltersRegistry](https://github.com/AdguardTeam/FiltersRegistry)
- Path: \`filters/filter_224_Chinese/filter.txt\`
- Git blob SHA: \`07d1a3c11ac797e62acf26e76a4e0179045def04\`
- Snapshot size: 758,180 bytes
- Source lines: 22,068
- Non-comment rule lines: 20,358

The line counts below are a static syntax classification of this snapshot, not a measure of useful or safe DNS coverage. Categories are exclusive under the audit classifier; upstream conditional directives and rule semantics are not fully interpreted by this first pass.

| Classification | Lines |
|---|---:|
| Exceptions | 1,153 |
| Cosmetic / element rules | 7,657 |
| Domain rules with modifiers | 703 |
| Simple hostname-pattern syntax | 5,966 (5,958 pass hostname validation; 8 are rejected) |
| Wildcard-bearing domain rules (not all are portable DNS wildcards) | 829 |
| URL / regex-like rules | 817 |
| Other / conditional / unsupported syntax | 3,233 |
| **Total** | **20,358** |

The 703 modifier-bearing domain rules include contextual conditions such as \`$third-party\` and \`$domain=\`. Removing those modifiers changes the original rule's meaning. DNS filtering cannot preserve request-party or page-domain context. Exceptions are also not automatically portable: they require exact precedence and scope handling.

## Mandatory exclusions

The following must not be flattened into DNS blocks:

- Cosmetic selectors, scriptlets, HTML filtering and other page-element rules.
- URL/path-specific and regular-expression rules.
- Rules with \`$third-party\`, \`$domain=\`, platform conditions or other request-context modifiers.
- Exceptions, unless their exact semantics are supported and independently reviewed.
- Wildcard patterns unless the exact matching behavior is supported by the target DNS client and the candidate is independently justified.

A syntactically simple \`||hostname^\` line is only a *candidate*. It may still be a first-party advertising endpoint, a shared API, a CDN object host, a login/payment dependency, or a service whose use is context-dependent. The source's own comments distinguish first-party ad-server cases; that is a warning against treating every hostname as a universally safe block.

## Reproducible audit

The scheduled build runs \`tools/audit_adguard_chinese.py\` against the current upstream snapshot and the generated NobleDNS subscription. It produces:

- \`dist/adguard-chinese-dns-audit.json\`: source fingerprint, exclusive syntax counts, and aggregate overlap results.
- \`dist/adguard-chinese-dns-candidates.csv\`: every simple hostname-pattern candidate, its source line, and whether an existing NobleDNS suffix/wildcard rule already covers it.

The overlap check is intentionally conservative and is not a complete emulation of every AdGuard client matching edge case. “Not covered” means only that the audit did not find a matching exact/parent suffix or supported wildcard in the current compiled list. It does **not** mean the candidate should be added.

The tool never modifies the production subscription. A future candidate may be promoted only after all of the following are documented:

1. Independent evidence that the hostname performs advertising, tracking, unwanted telemetry or malicious activity.
2. Exact source line and immutable source snapshot.
3. Confirmation that no first-party, shared-service, authentication, payment, CDN or update dependency is being blocked.
4. Demonstrated incremental value over HaGeZi Multi PRO, TIF Mini, AdGuard DNS Filter and AWAvenue Ads-only.
5. Reproducible test evidence and an essential-service regression case where relevant.
6. License and attribution review.

## Upstream references

- [AdGuard filter policy](https://adguard.com/kb/general/ad-filtering/filter-policy/)
- [AdGuard filter list overview](https://adguard.com/kb/general/ad-filtering/adguard-filters/)
- [AdGuard DNS filtering syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
- [HaGeZi DNS blocklist README](https://github.com/hagezi/dns-blocklists)

NobleDNS is independently maintained and is not affiliated with or endorsed by AdGuard or the maintainers of other upstream lists.
