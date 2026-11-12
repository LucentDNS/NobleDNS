# Quality and maintenance policy

## Project commitment

NobleDNS maintains **one balanced public edition**, designed with mainland China everyday network compatibility as a primary consideration. The project favors conservative, evidence-based DNS blocking over maximum rule count or aggressive blocking.

“Mainland-oriented” and “low false-positive” are design priorities. They are not measured performance claims until supported by a representative test corpus, reproducible client tests and published results. Do not describe the project as having a proven low false-positive rate while that evidence is absent.

## Quality priorities

1. **Compatibility first:** protect normal access to sign-in, payment, banking, messaging, push notifications, shopping, maps, video, CDN, software updates and public-service sites.
2. **Evidence before blocking:** a hostname's name, reputation label or appearance in an unreviewed list is not sufficient by itself to justify a new project-authored block.
3. **Conservative scope:** prefer narrowly scoped, well-supported DNS rules. Avoid broad parent-domain blocks when only a subdomain is implicated.
4. **Balanced coverage:** retain useful advertising and tracking protection without pursuing maximum blocking coverage at the expense of service reliability.
5. **Operational restraint:** keep one maintained edition, a bounded rule count, reproducible builds, clear provenance and a rollback path.

## Single-edition policy

- The only supported public product is the **NobleDNS Balanced Edition**.
- Do not create separate aggressive, strict, lite, regional or app-specific public variants unless the project explicitly revises this policy after evidence and maintenance-capacity review.
- The main subscription contains blocking rules and only the simple upstream exception rules accepted by the parser (`@@||domain^`). These source exceptions remain active because they express intentional upstream compatibility behavior. Complex or unsupported exception syntax is excluded. Every active exception is domain-validated, counted in the manifest, included in the subscription, and listed in `dist/allowlist-active.txt`. Project-authored allowlist additions still require independent evidence, narrow scope, cross-source conflict review and precedence regression tests.
- A source is not accepted merely because it is popular or large. Review its purpose, license, syntax, update behavior, rule scope, overlap, provenance and likely compatibility impact.
- Upstream lists currently configured are general-purpose lists, not mainland-China-specific datasets. Do not imply that their upstream maintainers have validated them for mainland services.

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

The current public build compiles supported blocking rules from the two configured general-purpose upstream snapshots. Automated parsing, syntax constraints, source drift checks and output validation reduce build risk, but they do not constitute manual, per-domain mainland compatibility review. Do not describe every compiled entry as individually vetted by NobleDNS. The stricter evidence and review steps below apply to confirmed corrections, project-authored additions and any future source change proposal.

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

The public DNS subscription accepts the documented AdGuard hostname-pattern forms `||domain^` and `||domain`, provided the hostname is a valid multi-label domain. AdGuard documents `||` as matching the beginning of a hostname, including subdomains, and `^` as the hostname-end separator. A missing `^` is not, by itself, a reason to discard a rule; the 69 retained bare-anchor rules remain listed for targeted client matching verification.

For the general filter-rule grammar, see [How to create your own ad filters](https://adguard.com/kb/general/ad-filtering/create-own-filters/); for DNS hostname matching, use the more specific [AdGuard DNS filtering syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/). Leading-dot forms (`.domain^` and `.domain`) are not among the hostname-pattern forms documented in that DNS-specific specification. NobleDNS therefore excludes them from the public subscription and records each original line in `parser-exclusions.csv` with the reason `unsupported_leading_dot_dns_syntax`. They are never rewritten as `||domain^`, because that would change their scope. The real upstream regression fixture contains 28 leading-dot records; all 28 must remain excluded unless the project formally expands its supported syntax based on authoritative documentation and client tests.

Complex modifiers, regexes, wildcard rules and unsupported exception forms remain excluded unless their semantics are explicitly implemented and tested. Active simple upstream exceptions are limited to `@@||domain^`, validated against the same domain rules, included in the main subscription and enumerated in `dist/allowlist-active.txt`.

Do not expand parser scope or alter source semantics merely to increase coverage or silence unverified reports.

## Automated publication checks

- Exactly the two approved sources load successfully and decode as strict UTF-8.
- Each source exceeds configured minimum size and parsed-block count.
- Per-source parsed rule count does not drift more than 15% from the last published manifest without review/override.
- Main output has valid supported syntax, no duplicates, nonzero rules and no more than 500,000 rules.
- Regression tests pass.
- Public artifacts are generated from the same validated build and checked before publication.
- Release assets are verified against the published files.

Automated checks do not replace testing every app, site, device or DNS client. Issues reported by users are reviewed and, when confirmed, added to regression coverage where appropriate.

## Feedback

If you find a site or app that does not work as expected, a domain that should be blocked but is not, or another rule-related problem, please report it through [GitHub Issues](https://github.com/LucentDNS/NobleDNS/issues). Include the affected hostname, site or app, exact affected function, DNS client and version, reproduction steps, and relevant sanitized DNS evidence. See [Feedback and rule improvement](FEEDBACK.md).


## Critical-service and efficacy regression gates

Every generated build is checked against a small, explicit regression corpus before publication:

- \`tests/fixtures/essential-domains.txt\` records 72 representative financial, payment, carrier, public-service, mainstream-app and device-update hostnames. The gate rejects direct or parent-domain blocking coverage unless an active exception also covers that hostname.
- \`tests/fixtures/known-ads.txt\` records 20 representative advertising-infrastructure hostnames. The gate verifies that each remains covered by a blocking rule and is not neutralized by an active exception.
- The generated subscription is checked for supported syntax only: \`||domain^\`, \`||domain\`, and \`@@||domain^\`. Bare hostname-start anchors are intentionally retained and validated; they are not treated as malformed rules.
- The existing source-level 15% drift gate remains. In addition, additions and removals are each capped at 3,000 rules per build. The existing explicit \`--allow-large-change\` workflow override is the only bypass and must follow human review.

These are regression sentinels, not a representative false-positive or true-positive measurement. The 72 service hostnames do not cover every service or app, and the 20 ad hostnames do not prove comprehensive blocking efficacy. Client-specific DNS semantics and real-world traffic still require separate testing.
