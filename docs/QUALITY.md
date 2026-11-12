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
- The main subscription remains block-only. Exceptions and allowlist candidates are reviewed separately; they must not be silently merged into the main blocklist.
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

The compiler supports the documented AdGuard DNS forms: ||domain^, ||domain, .domain^ and .domain when the hostname is a valid multi-label DNS name. AdGuard documents ||example.org^ as blocking the apex and all subdomains, while .example.org blocks subdomains only and leaves the apex domain allowed. NobleDNS preserves these forms exactly; it never rewrites leading-dot rules into apex-and-subdomain blocks. The ||domain form without an explicit ^ is retained unchanged from upstream and listed for targeted compatibility review. AdGuard documents || as a hostname-start anchor and ^ as the hostname-end separator; the 69 retained bare-anchor rules therefore need targeted client verification before we claim broad compatibility. See the [official AdGuard DNS filtering syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/).

The real upstream leading-dot regression fixture contains 28 source records: 23 .domain^ rules, 4 .domain rules and 1 trailing-dot rule that must remain excluded. Parser regression coverage does not establish broad DNS-client compatibility. Live compatibility testing remains part of ongoing maintenance.

Do not expand parser scope unless tests prove semantic equivalence for the target clients. Do not silently turn unsupported patterns into ordinary domain blocks.

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
