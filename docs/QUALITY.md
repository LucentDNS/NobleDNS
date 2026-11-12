# Quality and maintenance policy

## Project commitment

NobleDNS is a publicly maintained DNS filtering rule set for everyday use. The project combines established upstream sources and applies automated parsing, validation, regression testing, change detection and reproducible publishing.

The goal is practical protection against advertising, tracking, telemetry and other unwanted domains. Rule counts alone do not establish protection quality; maintenance decisions are based on source evidence, rule behavior and regression results.

## Required maintenance checks

1. **Blocking coverage:** build and maintain a reviewed, labeled corpus for advertising, tracking, telemetry and threat-domain categories. Synthetic parser fixtures must not be presented as evidence of real-world blocking efficacy.
2. **Service behavior:** investigate reports involving sign-in, payment, banking, messaging, push, app updates, video/CDN and domestic services.
3. **Compatibility:** preserve documented rule semantics and test supported DNS filtering clients with reproducible test cases.
4. **Reliability:** repeatable builds, strict source validation, stable subscription format and bounded resource use.
5. **Change safety:** source hashes/counts, drift gates, regression tests, reviewable reports and rollback capability.

## Current verification status

The current automated suite exercises parser and configuration behavior, including supported rule forms, syntax preservation, malformed-input rejection, IDNA handling, duplicate handling, source configuration and drift-gate behavior. The build workflow also validates downloaded sources, generated output, rule-count limits, licensing metadata and published artifact integrity.

The project does **not** currently claim:

- A measured true-positive or false-positive rate.
- An independently curated and continuously maintained ground-truth dataset for advertising, tracking, telemetry and threat domains.
- Live DNS integration testing across AdGuard for Android, AdGuard Home, dnsmasq, or other clients.
- A comprehensive real-world website/app compatibility matrix.

These are known evidence gaps, not claims of failure. They must remain visible until actual test data and reproducible results exist. Do not infer filtering effectiveness from rule count, parser tests, source reputation or a successful build.

## Current parser scope

The compiler supports the documented AdGuard DNS forms `||domain^`, `||domain`, `.domain^` and `.domain` when the hostname is a valid multi-label DNS name. AdGuard documents `||example.org^` as blocking the apex and all subdomains, while `.example.org` blocks subdomains only and leaves the apex domain allowed. NobleDNS preserves these forms exactly; it never rewrites leading-dot rules into apex-and-subdomain blocks. The `||domain` form without an explicit `^` is retained from upstream and listed for targeted compatibility review because it lacks an explicit end boundary. AdGuard documents `||` as a hostname-start anchor and `^` as the hostname-end separator; preserving the source text avoids silently changing upstream intent, but client behavior for the 69 retained bare-anchor rules still needs targeted verification. See the [official AdGuard DNS filtering syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/).

The real upstream leading-dot regression fixture contains 28 source records: 23 `.domain^` rules, 4 `.domain` rules and 1 trailing-dot rule that must remain excluded. Parser regression coverage does not establish broad DNS-client compatibility. Live compatibility testing remains part of ongoing maintenance.

Do not expand parser scope unless tests prove semantic equivalence for the target clients. Do not silently turn unsupported patterns into ordinary domain blocks.

## Automated publication checks

- Exactly the two approved sources load successfully and decode as strict UTF-8.
- Each source exceeds configured minimum size and parsed-block count.
- Per-source parsed rule count does not drift more than 15% from the last published manifest without review/override.
- Main output has valid supported syntax, no duplicates, nonzero rules and no more than 500,000 rules.
- Regression tests pass.
- Public artifacts are generated from the same validated build and checked before publication.
- Release assets are verified against the published files.

Automated checks verify the build and the rules covered by the regression corpus. They do not replace testing every app, site, device or DNS client. Issues reported by users are reviewed and, when confirmed, added to regression coverage where appropriate.

## Feedback

If you find a site or app that does not work as expected, a domain that should be blocked but is not, or another rule-related problem, please report it through [GitHub Issues](https://github.com/LucentDNS/NobleDNS/issues). Include the affected hostname, site or app, DNS client and version, reproduction steps, and relevant sanitized DNS evidence. See [Feedback and rule improvement](FEEDBACK.md).
