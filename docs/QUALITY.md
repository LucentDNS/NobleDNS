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
- Upstream exception rules remain review-only and are never activated automatically. A separate project-maintained `config/allowlist.txt` is the only input allowed to generate active `@@||domain^` exceptions; each entry must be supported by reproducible compatibility evidence. The allowlist starts empty. Active exceptions are included in the main subscription and covered by tests.
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

The compiler publishes only the two documented AdGuard DNS hostname-anchor forms: `||domain^` and `||domain`, provided the hostname is a valid multi-label DNS name. The bare-anchor form without an explicit `^` is valid syntax and is preserved unchanged; it is not discarded merely for lacking an end separator.

Leading-dot forms (`.domain^` and `.domain`) are excluded from the public output and recorded in `parser-exclusions.csv` as unsupported by NobleDNS's selected DNS syntax contract. They are not rewritten into other rules. The real upstream regression fixture contains 28 leading-dot records; all 28 must remain excluded unless a future standards review explicitly expands the supported syntax and tests prove the behavior.

The 69 retained `||domain` rules are inventoried in `syntax-review.csv` for targeted client matching verification. This is a compatibility-review item, not a claim that the syntax is invalid. See the [official AdGuard DNS filtering syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/).

## Allowlist policy

The upstream `@@` exceptions are preserved in `whitelist-review.txt` for source-level audit only. They are not activated automatically because an upstream exception may override a block supplied by another source.

Project-approved exceptions are maintained separately in `config/allowlist.txt`. Each non-comment line must be a valid exact hostname. The builder validates the entries, removes matching block rules for that hostname and its subdomains, and emits a corresponding `@@||hostname^` exception in the main subscription. The file is intentionally empty until a compatibility issue is reproduced and reviewed. Do not add broad parent domains without evidence.

Do not expand parser scope or allowlist entries merely to increase coverage or silence unverified reports.

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
