# Changelog

## 1.0.0-rc3 — automation candidate

- Consolidated the RC2.2 domain-anchor parser behavior into one fail-closed builder.
- Kept the two approved upstreams only: AdGuard DNS Filter and HaGeZi Multi Normal.
- Preserved `||domain` and `||domain^` syntax without rewriting one into the other.
- Added strict UTF-8 source validation, source size limits, source-count drift checks, rule-set delta checks, a 500,000-rule ceiling and atomic `latest` replacement.
- Added parser/config regression tests and a daily GitHub Actions build/release workflow.
- Kept exceptions separate from the main block-only subscription.
- Release channel remains `candidate`; real-world compatibility and false-positive qualification are outstanding.
