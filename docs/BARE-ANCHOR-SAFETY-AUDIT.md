# Bare-anchor rule safety audit

> Snapshot: NobleDNS main build 1.0.3, source and subscription identities are recorded in the GitHub Actions build-audit artifact.
> This report is a narrow static regression check, not a claim of complete client compatibility.

## Why these rules need a separate check

The current subscription contains 69 supported AdGuard DNS rules in the form `||hostname` without a trailing `^`. They are all inherited from the AdGuard DNS Filter source snapshot.

These rules are not automatically invalid and are not rewritten. However, unlike `||hostname^`, a bare hostname-start anchor does not assert an end-of-hostname separator. It can match the anchored name, its subdomains, and a longer hostname beginning with the same text. For example, the supported offline model treats `example.com.attacker.test` as matching `||example.com`. This makes a positive-service regression check particularly important.

## Current snapshot result

- Bare-anchor rules: **69**
- Source attribution: **69/69 matched to the AdGuard DNS Filter snapshot**
- Critical-service sentinels checked: **72**
- Matches against the current essential-service sentinel set: **0**
- Production rules modified: **0**

The 72 sentinels cover mainland banks and payments, telecom carriers, government services, mainstream applications, and operating-system/update domains. They are a small curated regression set, not a comprehensive inventory of all critical hostnames.

## Interpretation and limitations

- Zero sentinel matches means only that these 69 rules do not match the 72 exact hostnames in this fixture under the project's documented offline matcher.
- It does not prove the 69 rules are safe across all applications, subdomains, CNAME chains, regions, or client implementations.
- A hostname can be operationally important even if it is not in the current sentinel fixture.
- Hostname tokens such as `api`, `config`, `logs`, `events`, `mssdk`, `cdn`, and `proxy` are prompts for further function-specific investigation, not proof of legitimate or unwanted behavior.
- No rule should be changed to add or remove `^` solely to make a static test pass. Any semantic change requires source-level evidence, an equivalent hostname test, and verification on supported clients.

## Automation

`tools/audit_bare_anchor_safety.py` runs against the exact compiled subscription and downloaded AdGuard source snapshot on every build. It records source line numbers and every match against the critical-service fixture. A hit fails the build so a potential critical-service conflict is reviewed before publication.

The generated `bare-anchor-audit.csv` is archived with the build evidence and published as a diagnostic artifact. The test suite also checks the matcher semantics and asserts that the current 69 bare anchors do not hit the current 72 essential-service sentinels. The companion [app compatibility risk triage](BARE-ANCHOR-APP-RISK-TRIAGE.md) now tracks 17 unresolved hostnames (4 P0 and 13 medium-priority investigations) with source evidence and explicit limitations; none is treated as a confirmed NobleDNS false positive. The 69-rule worksheet assigns 4 P0, 19 P1 and 46 P2 review priorities; these are triage tiers, not safety classifications.
