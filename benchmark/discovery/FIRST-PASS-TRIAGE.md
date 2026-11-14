# First-pass triage queue (not a scored corpus)

This file is a maintainer-generated **first-pass work queue** over the 100-domain HTTP Archive discovery seed. It is not a blocklist, allowlist, or benchmark ground truth.

## Evidence used

- Request reach and cookie-setting observations: HTTP Archive 2026-06 aggregate, included in this directory.
- Ownership and broad entity category: webtracking.org `webtracking-data` dataset `entities.json`, pinned at commit `282d07ce9d4656478815ad7e83869f4bc2262cb5`, dataset version 2026-06.1, updated 2026-08-06, CC BY 4.0. Attribution: webtracking.org, https://webtracking.org.
- The source entity map says its category describes the parent entity, not a verdict on each hostname's function. Therefore this triage does not label any domain as safe to block.

## Preliminary lanes

- `ads_owner_review`: the parent entity is categorized as `ads`; prioritize for hostname-level review. This does **not** mean the individual hostname is an ad endpoint and is not approval to block it.
- `infra_platform_owner_review`: the parent entity is categorized as `infra` or `platform`; prioritize for essential-function and false-positive review. This is not a verified allow label.
- `mixed_owner_review`: social, martech or other context-dependent parent entities; require hostname-level evidence.
- `unmapped`: no owner record in this source; remain unresolved.

Every row is marked `primary_triage_only`. A second distinct reviewer and additional independent evidence are still required before any row enters the scored benchmark corpus. The queue does not change NobleDNS production rules.

## Triage totals

- Ads-owner candidates: 45
- Infrastructure/platform controls: 15
- Mixed/contextual review items: 16
- Unmapped / unresolved: 24
- Total: 100

## Important cautions

1. A parent company category is not a domain-level purpose classification.
2. Cookie-setting frequency is not proof of tracking or advertising.
3. A domain may serve multiple functions; shared root domains must not be blocked based on a vendor label.
4. The source entity map is a discovery aid. Do not use it alone to claim TP/FP, precision, recall or user-visible effectiveness.
5. The 100-domain crawl is a web sample and does not represent mainland-China apps, all regions or all users.

## Next maintainer actions

1. Resolve the adtech candidates at hostname/function granularity using vendor documentation, public endpoint evidence and observed request context.
2. Resolve controls by checking essential dependencies and service roles.
3. Exclude ambiguous root domains from scoring until evidence supports a precise hostname.
4. Obtain independent second review; unresolved rows remain unscored.
5. Only then populate `tests/fixtures/reviewed-benchmark-corpus.csv`.
