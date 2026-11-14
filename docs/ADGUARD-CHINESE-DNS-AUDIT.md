# AdGuard Chinese filter: DNS-scope audit

> Status: audit-only. AdGuard Chinese is **not** a NobleDNS production source.

## Decision

Do not add AdGuard Chinese wholesale and do not add EasyList China as a second regional source. AdGuard documents its Chinese filter as originally based on EasyList China and subsequently maintained through its own user feedback and changes. The two are therefore not independent coverage layers that should simply be stacked.

AdGuard Chinese is primarily a browser/content filter. NobleDNS is a hostname-level DNS list. Only narrowly selected hostnames with independent evidence of unwanted DNS behavior could ever be considered for NobleDNS; this audit does not approve any rule.

## Snapshot inspected

- Upstream file: [AdGuard Chinese filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt)
- Repository: [AdguardTeam/FiltersRegistry](https://github.com/AdguardTeam/FiltersRegistry)
- Path: `filters/filter_224_Chinese/filter.txt`
- CI snapshot SHA-256: `acba900510ad8403977fb2c96a82e85d8cedfce88e5ccf37341008ae94034c2a`
- Snapshot size: 758,767 bytes
- Source lines: 22,068
- Non-comment rule lines: 20,359
- Matching NobleDNS build: v1.0.7, subscription SHA-256 `635d5fcab5605459f5d1df59911de26dde5e6f218b2ce5acd9ed812e03cece47`
- Audit run: [GitHub Actions #578](https://github.com/LucentDNS/NobleDNS/actions/runs/43579323077), [PR #76](https://github.com/LucentDNS/NobleDNS/pull/76)

The line counts below are a static syntax classification of this snapshot, not a measure of useful or safe DNS coverage. Categories are exclusive under the audit classifier; upstream conditional directives and rule semantics are not fully interpreted by this first pass.

| Classification | Lines |
|---|---:|
| Exceptions | 1,153 |
| Cosmetic / element rules | 7,657 |
| Domain rules with modifiers | 703 |
| Simple hostname-pattern syntax passing validation | 5,959 |
| Invalid simple hostname-pattern lines | 8 |
| Wildcard-bearing domain rules (not all are portable DNS wildcards) | 829 |
| URL / regex-like rules | 819 |
| Other domain syntax | 3,103 |
| Other / conditional / unsupported syntax | 128 |
| **Total** | **20,359** |

The 703 modifier-bearing domain rules include contextual conditions such as `$third-party` and `$domain=`. Removing those modifiers changes the original rule's meaning. DNS filtering cannot preserve request-party or page-domain context. Exceptions are also not automatically portable: they require exact precedence and scope handling.


## Results from the first recurring CI audit

The CI run above extracted **5,959 syntactically simple, valid hostname candidates**. The conservative suffix/wildcard comparison found:

- **5,954 already covered** by the current NobleDNS subscription.
- **5 not covered** by that comparison.
- **0 candidates approved or added** to the production subscription.

The four uncovered candidates were individually triaged:

| Candidate | Source context / independent signal | Decision |
|---|---|---|
| `kqzyfj.com` | Appears in an advertising-domain blocklist and is identified as a CJ Affiliate redirect/tracking domain. Blocking the whole redirect domain can interfere with legitimate affiliate links and attribution. | Hold; no production import without a narrower, demonstrably safe DNS use case |
| `h1.azuimeh.top` | No sufficiently reliable independent evidence was found to establish its current purpose and impact. | Unresolved; do not block on source presence alone |
| `symaa.cn` | Appears under an upstream `NOT_OPTIMIZED PLATFORM(ios, ext_android_cb, ext_safari)` condition. DNS cannot preserve this client/platform scope; the domain's purpose is not independently established. | Exclude from DNS conversion |
| `https-filtering-check.adtidy.org` | The upstream section labels this endpoint as an AdGuard HTTPS-filtering detection check, not an advertising hostname. | Do not block; preserve legitimate security/filter diagnostics |
| `uyux77jurw.com` | It appears in a cluster of unrelated, opaque-looking hostnames, but no reliable independent reputation or behavioral evidence was found. A name pattern is not proof. | Unresolved; hold for evidence, do not import |

The `kqzyfj.com` corroborating references are [IPFire's advertising-domain entry](https://www.ipfire.org/dbl/lists/ads/domains/kqzyfj.com) and an [affiliate-link reference identifying CJ's rotating redirect domains](https://dailyintelservice.com/learn/affiliate-link-anatomy-identify-a-network-from-a-url). These are supporting signals, not proof that the domain should be globally blocked.

This result shows that the Chinese filter's simple hostname rules add almost no obvious *syntactic* coverage to the current NobleDNS build. It does not prove the 5,954 covered rules are all desirable, nor that the four uncovered rules should be added. The full candidate CSV preserves each upstream line for future evidence-based review. The fifth unmatched hostname appeared in the latest upstream snapshot; it has not been promoted or treated as malicious.

## Mandatory exclusions

The following must not be flattened into DNS blocks:

- Cosmetic selectors, scriptlets, HTML filtering and other page-element rules.
- URL/path-specific and regular-expression rules.
- Rules with `$third-party`, `$domain=`, platform conditions or other request-context modifiers.
- Exceptions, unless their exact semantics are supported and independently reviewed.
- Wildcard patterns unless the exact matching behavior is supported by the target DNS client and the candidate is independently justified.

A syntactically simple `||hostname^` line is only a *candidate*. It may still be a first-party advertising endpoint, a shared API, a CDN object host, a login/payment dependency, or a service whose use is context-dependent. The source's own comments distinguish first-party ad-server cases; that is a warning against treating every hostname as a universally safe block.

## Reproducible audit

The scheduled build runs `tools/audit_adguard_chinese.py` against the current upstream snapshot and the generated NobleDNS subscription. It produces:

- `dist/adguard-chinese-dns-audit.json`: source fingerprint, exclusive syntax counts, and aggregate overlap results.
- `dist/adguard-chinese-dns-candidates.csv`: every simple hostname-pattern candidate, its source line, and whether an existing NobleDNS suffix/wildcard rule already covers it.

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
