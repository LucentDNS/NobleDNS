# Quality and maintenance policy

## Project commitment

NobleDNS maintains **one balanced public edition**, designed with mainland China everyday network compatibility as a primary consideration. The project favors conservative, evidence-based DNS blocking over maximum rule count or aggressive blocking.

“Mainland-oriented” and “low false-positive” are design priorities, not measured performance claims. NobleDNS now maintains a small automated regression corpus: 72 essential-service hostnames are checked for unintended blocking, and 20 known advertising-infrastructure hostnames are checked for continued blocking coverage. This is useful regression protection, but it is not representative of all mainland services and does not establish a measured real-world false-positive or true-positive rate. Do not describe the project as having a proven low false-positive rate.

## Quality priorities

1. **Compatibility first:** protect normal access to sign-in, payment, banking, messaging, push notifications, shopping, maps, video, CDN, software updates and public-service sites.
2. **Evidence before blocking:** a hostname's name, reputation label or appearance in an unreviewed list is not sufficient by itself to justify a new project-authored block.
3. **Conservative scope:** prefer narrowly scoped, well-supported DNS rules. Avoid broad parent-domain blocks when only a subdomain is implicated.
4. **Balanced coverage:** retain useful advertising and tracking protection without pursuing maximum blocking coverage at the expense of service reliability.
5. **Operational restraint:** keep one maintained edition, a bounded rule count, reproducible builds, clear provenance and a rollback path.

## Single-edition policy

- The only supported public product is the **NobleDNS Balanced Edition**.
- Do not create separate aggressive, strict, lite, regional or app-specific public variants unless the project explicitly revises this policy after evidence and maintenance-capacity review.
- The main subscription contains supported blocking rules plus only exceptions permitted by `data/exception-review.csv`. The 11 inherited exceptions from the audited 2026-11-12 snapshot are a frozen, temporary compatibility baseline: they remain active to avoid silently changing existing behavior, but are still marked `pending` and are **not** NobleDNS approvals. The build rejects unregistered upstream exception additions or removals. Any exception outside that exact legacy baseline must be independently reviewed and recorded as `approved` with reviewer, UTC date, rationale, evidence URL and scope assessment before activation. Complex or unsupported exception syntax remains excluded.
- A source is not accepted merely because it is popular or large. Review its purpose, license, syntax, update behavior, rule scope, overlap, provenance and likely compatibility impact.
- HaGeZi Multi PRO Mini and AdGuard DNS Filter are general-purpose lists, while HaGeZi TIF Mini is a threat-intelligence feed and AWAvenue is an advertising-focused supplement. None is a mainland-China-specific dataset. Do not imply that their upstream maintainers have validated them for mainland services.

## Parent/child compression and public-suffix safety

The build removes a child rule only when all of the following are true:

- The child and parent are both exact simple hostname rules in `||domain^` form.
- The parent rule is present in the same merged input set.
- The parent is not a public suffix according to the pinned Mozilla Public Suffix List snapshot.
- The relationship is a true DNS-label suffix relationship, not a string-suffix coincidence.

The PSL snapshot is pinned to commit `c3a53eed2cc49353c5fb5c30536186795d5c451b` and checked against SHA-256 `7379dee58164b5f7cda5e37f2cc85b3d1754245dc313178eef5cbdcaca758650` on every build. Both ICANN and PRIVATE sections are included, and exact, wildcard and exception PSL rules are interpreted. If the snapshot is missing, altered or malformed, the build fails closed.

Bare anchors (`||domain`), wildcard rules, `$important` rules, exceptions and other syntax are never compressed. Every removed rule is listed with its covering parent and source provenance in `domain-compression-audit.csv`. The audit is deterministic and the compression step is idempotent. The first rollout permits only an exact compression-only migration of at most 10,000 removals when all upstream source fingerprints are unchanged; ordinary source and rule drift limits remain in force afterward.

This transformation reduces redundant entries; it does not add new blocking scope beyond an existing parent rule. It is not a dead-domain detector. Dead-domain scanning is intentionally not part of the scheduled build because the upstream full-list scan is too expensive for the available GitHub Actions budget and can delay the entire pipeline.

## Mainland-use compatibility review

Review reports and test cases across these service categories:

- Identity, account registration and sign-in.
- Banking, payment and financial services.
- Messaging, voice/video calls and push notifications.
- E-commerce, delivery and local-life services.
- Maps, transport, travel and location-related services.
- Video, music, live streaming and content delivery networks.
- App stores, software downloads, update checks and device-vendor services.
- Government, education, healthcare appointment and other public-service portals.

These categories define review priorities; they do not imply that every named service or provider has been tested. Record exact hostnames and affected functions, and distinguish a confirmed block-rule false positive from resolver failure, routing, TLS, application or upstream service problems.

## Current compilation model

The current public build compiles supported blocking rules from four configured sources: HaGeZi Multi PRO Mini, HaGeZi TIF Mini, AdGuard DNS Filter, and AWAvenue Ads Rule (Only Ads). Multi PRO is the sole HaGeZi Multi tier because the upstream tiers are cumulative; Multi Normal is not duplicated alongside it. TIF Mini is a separate threat-intelligence add-on for malware and phishing, not another Multi tier. AdGuard DNS Filter remains a separately audited DNS-layer supplement, not a requirement for AdGuard client compatibility. AWAvenue is a focused advertising-only supplement. Automated parsing, syntax constraints, source drift checks and output validation reduce build risk, but they do not constitute manual, per-domain mainland compatibility review. Do not describe every compiled entry as individually vetted by NobleDNS. The build manifest records exact source-only rule counts and pairwise exact overlap so maintainers can identify redundant or complementary inputs. These are string-level statistics, not semantic-overlap or efficacy measurements. The stricter evidence and review steps below apply to confirmed corrections, project-authored additions and any future source change proposal.

## Chinese and regional filter handling

NobleDNS does not treat a browser-language filter as a DNS blocklist. AdGuard's own DNS build configuration imports the Chinese filter's dedicated `adservers.txt` and `adservers_firstparty.txt` sections, applies the shared DNS exclusions, and then applies explicit transformations. The third-party section's own comments restrict it to full-domain advertising networks used in third-party contexts; the first-party section is separately limited to full advertising subdomains hosted on non-advertising sites.

The pinned [AdGuard DNS filter configuration](https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/544efcd7692a0092f924494662ddea76787036f9/configuration.json) also takes EasyList China through a narrow third-party ad-server extraction: it keeps only full-domain `||` / `@@||` rules, excludes rules carrying `$third-party`, then removes remaining modifiers and validates the result. This is a DNS-specific extraction, not a recommendation to import the full browser filter. AdGuard's [HostlistCompiler documentation](https://github.com/AdguardTeam/HostlistCompiler) explicitly warns that blindly removing `$third-party` from traditional rules causes many false positives; the exclusion step before modifier removal is deliberate. See the pinned [Chinese third-party section](https://github.com/AdguardTeam/AdguardFilters/blob/f2d7ee9c4deec50a05cbbdd5cc587ac8935c1987/ChineseFilter/sections/adservers.txt) and [Chinese first-party section](https://github.com/AdguardTeam/AdguardFilters/blob/6706124fbbab26689bbb3075696c76b57c9f61a0/ChineseFilter/sections/adservers_firstparty.txt).

The existing AdGuard DNS Filter source already incorporates those DNS-oriented Chinese sections and its curated EasyList China extraction. NobleDNS's exact-rule comparator finds the supported hostname subset of the audited AdGuard DNS Filter snapshot fully covered. Therefore, do not add AdGuard Chinese or EasyList China as a second production source. The full AdGuard Chinese browser filter remains audit-only; cosmetic, URL, regex, platform and request-context rules are not flattened into DNS rules. In particular, never remove `$third-party` from arbitrary browser rules without preserving their scope and reviewing false-positive risk.

A concrete example is `kqzyfj.com`: it appears in the broad Chinese third-party ad-server section but is excluded by AdGuard DNS's shared [exclusions file](https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/c13fac30dc50cc57d45b103f29a76d8aa12fda19/Filters/exclusions.txt). The linked [EasyList issue #9445](https://github.com/easylist/easylist/issues/9445) documents that it is used as a click-through redirect for RoboForm. This is why NobleDNS does not convert every domain in a browser filter into a global DNS block. See [the detailed AdGuard Chinese DNS audit](ADGUARD-CHINESE-DNS-AUDIT.md).

## Rule acceptance and correction

For every proposed rule addition, removal or narrowing:

1. Record the source and exact source line or upstream commit/snapshot.
2. Identify the hostname and the observed advertising, tracking or security behavior.
3. Check whether the rule is already covered, duplicated, superseded or contradicted by a legitimate service dependency.
4. Prefer the narrowest hostname scope supported by evidence.
5. Assess effects on apex domains, subdomains, shared hosting, CDNs and common service dependencies.
6. Add a regression case for every confirmed correction.
7. Run the complete tests and inspect the generated diff before publication.
8. Document material changes and preserve rollback capability.

For a reported false positive, reproduce with NobleDNS enabled and disabled while keeping the resolver, network and client settings constant. Do not add broad allowlist exceptions to silence a report without understanding the affected hostname and scope.

## Evidence and measurement roadmap

The project does **not** currently claim:

- A measured true-positive or false-positive rate.
- An independently curated and continuously maintained ground-truth corpus for advertising, tracking, telemetry and threat domains.
- Live DNS integration testing across AdGuard for Android, AdGuard Home, dnsmasq or other clients.
- A comprehensive real-world mainland website/app compatibility matrix.

To support future quality claims, build a reviewed corpus with at least these labels: confirmed ad/tracker, confirmed unwanted telemetry, confirmed malicious or threat infrastructure, legitimate or essential service, and unresolved. Each entry should include evidence, source, review date, confidence, affected service/function and a regression test where appropriate. Do not count unresolved entries as confirmed blocks or confirmed false positives.

Publish measurements only with their denominator, sampling method, test date, client/resolver versions, corpus revision and known limitations. Separate rule syntax/client compatibility, false-positive observations, missed-block observations, reviewed-corpus coverage, and user-reported issues with their verification status. A small or biased sample must not be presented as representative of all mainland users or all domestic apps.

## Current verification status

The current automated suite exercises parser and configuration behavior, including supported rule forms, syntax preservation, malformed-input rejection, IDNA handling, duplicate handling, source configuration and drift-gate behavior. The build workflow also validates downloaded sources, generated output, rule-count limits, licensing metadata and published artifact integrity.

These checks verify build integrity and the rules covered by the regression corpus. They do not measure real-world filtering efficacy. The [DNS client compatibility test plan](COMPATIBILITY-TEST-PLAN.md) defines a controlled procedure for testing syntax semantics without using production domains.

## Current parser scope

The public DNS subscription accepts documented AdGuard hostname-pattern forms `||domain^` and `||domain`, supported hostname wildcards with a static suffix (including two upstream wildcard anchors without an explicit end separator), and `$important` on supported hostname block rules. Static bare anchors and wildcard anchors are audited as separate syntax classes; neither is silently rewritten. Hostnames must pass strict multi-label validation. AdGuard documents `||` as matching the beginning of a hostname, including subdomains, and `^` as the hostname-end separator. A missing `^` is not, by itself, a reason to discard a rule; the retained bare-anchor rules in the current audited snapshot remain listed for targeted client matching verification.

For the general filter-rule grammar, see [How to create your own ad filters](https://adguard.com/kb/general/ad-filtering/create-own-filters/); for DNS hostname matching, use the more specific [AdGuard DNS filtering syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/). Leading-dot forms (`.domain^` and `.domain`) are not among the hostname-pattern forms documented in that DNS-specific specification. NobleDNS therefore excludes them from the public subscription and records each original line in `parser-exclusions.csv` with the reason `unsupported_leading_dot_dns_syntax`. They are never rewritten as `||domain^`, because that would change their scope. The real upstream regression fixture contains 28 leading-dot records; all 28 must remain excluded unless the project formally expands its supported syntax based on authoritative documentation and client tests.

The compiler preserves documented hostname wildcards only when the final label and at least one other label are static and the pattern passes strict hostname validation; dynamic-suffix and path-like wildcard patterns remain excluded. The documented `$important` modifier is preserved on supported hostname block rules. Regexes, `$badfilter` and unsupported exception forms remain excluded until their full semantics are implemented and tested. Active simple upstream exceptions remain limited to `@@||domain^`, validated against the same domain rules, included in the main subscription and enumerated in `dist/allowlist-active.txt`.

Do not expand parser scope or alter source semantics merely to increase coverage or silence unverified reports.

## Automated publication checks

- Exactly the four approved sources load successfully and decode as strict UTF-8.
- Each source exceeds configured minimum size and parsed-block count.
- Per-source parsed rule count does not drift more than 15% from the last published manifest without review/override.
- Main output has valid supported syntax, no duplicates, nonzero rules and remains within the configured capacity guard.
- Regression tests pass.
- Parsed upstream exceptions exactly match the review register; only approved exceptions and the frozen legacy pending baseline can be emitted.
- Public artifacts are generated from the same validated build and checked before publication.
- Release assets are verified against the published files.

Automated checks do not replace testing every app, site, device or DNS client. Issues reported by users are reviewed and, when confirmed, added to regression coverage where appropriate.

## Exception rule governance

DNS exception rules can override matching block rules. The current 11 simple upstream exceptions are recorded in [`data/exception-review.csv`](../data/exception-review.csv) and documented in the [exception review procedure](EXCEPTION-REVIEW.md). They remain `pending` and active only as an explicitly frozen legacy baseline; their upstream presence is provenance, not proof of necessity or appropriate scope. The build now checks the parsed exception set against this register and fails closed on additions, removals, malformed records, or unreviewed new entries. A new exception can become active only after a complete `approved` record is supplied. This gate prevents silent expansion; it does not retroactively approve the 11 legacy entries.

## Feedback

If you find a site or app that does not work as expected, a domain that should be blocked but is not, or another rule-related problem, please report it through [GitHub Issues](https://github.com/LucentDNS/NobleDNS/issues). Include the affected hostname, site or app, exact affected function, DNS client and version, reproduction steps, and relevant sanitized DNS evidence. See [Feedback and rule improvement](FEEDBACK.md).


## Critical-service and efficacy regression gates

Every generated build is checked against a small, explicit regression corpus before publication:

- `tests/fixtures/essential-domains.txt` records 72 representative financial, payment, carrier, public-service, mainstream-app and device-update hostnames. The gate rejects direct or parent-domain blocking coverage unless an active exception also covers that hostname.
- `tests/fixtures/known-ads.txt` records 20 representative advertising-infrastructure hostnames. The gate verifies that each remains covered by a blocking rule and is not neutralized by an active exception.
- The generated subscription is checked for supported syntax, including `||domain^`, `||domain`, validated hostname wildcards, `$important` block rules, and simple `@@||domain^` exceptions. Bare hostname-start anchors are intentionally retained and validated; they are not treated as malformed rules.
- The existing source-level 15% drift gate remains. In addition, additions and removals are each capped at 3,000 rules per build. The existing explicit `--allow-large-change` workflow override is the only bypass and must follow human review.

These are regression sentinels, not a representative false-positive or true-positive measurement. The 72 service hostnames do not cover every service or app, and the 20 ad hostnames do not prove comprehensive blocking efficacy. Client-specific DNS semantics and real-world traffic still require separate testing.
