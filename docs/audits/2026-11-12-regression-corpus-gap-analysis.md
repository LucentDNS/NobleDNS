# NobleDNS regression-corpus gap analysis — 2026-11-12

> Research and test-design document only. This change does not alter the public rule list or any production fixture.

## 1. Current regression corpus

The current public quality gates use:

- 72 essential-service hostnames in `tests/fixtures/essential-domains.txt`.
- 20 known advertising-infrastructure hostnames in `tests/fixtures/known-ads.txt`.

The automated gate checks suffix-aware blocking coverage against the essential set and blocking coverage against the known-ad set. This is valuable regression protection, but the test sets are small, manually enumerated sentinels. Passing them does not establish a measured real-world false-positive or true-positive rate.

The 20 known-ad fixtures are predominantly global advertising networks. They do not constitute a representative Mainland China advertising/SDK corpus. The 72 essential fixtures are useful apex/service sentinels, but do not comprehensively cover subdomains and individual app functions such as login, payment, push, media playback, update delivery, cloud sync and image/CDN loading.

## 2. Gap classification

| Area | Current protection | Remaining gap |
|---|---|---|
| Banks and payment | Representative apex/service hostnames | Login, payment authorization, risk control, callbacks, certificates and regional endpoints |
| Government and public services | Small set of public hostnames | More provincial/municipal services and their identity/CDN dependencies |
| Carrier services | Carrier apex domains | Recharge, account, billing, SMS/voice, eSIM and customer-service flows |
| Mainland apps | Mainstream service apexes | Per-function hosts and app-version-specific dependencies |
| Device vendors | Major vendor domains | OTA, app store, push, telemetry, account and cloud functions |
| Video and live streaming | Major service apexes | Playback manifests, media CDN, comments, recommendations and live interaction |
| Domestic advertising | No curated Mainland-specific positive fixture group | Independently verified ad endpoints and test evidence |
| Tracking/analytics | No separate ground-truth fixture group | Distinguish ad measurement from crash reports, fraud prevention, diagnostics and required telemetry |
| Threat protection | No separate curated threat corpus in these two files | Malware/phishing/C2 data needs its own evidence and freshness policy |
| DNS-client semantics | Static parser/output checks | Real-client testing for documented syntax forms remains NOT TESTED |

## 3. Do not turn candidate lists into ground truth

The 37-hostname advertising review at `2026-11-12-advertising-candidate-review.md` is a research queue, not a confirmed-ad dataset. It contains name-based and source-based signals, including product namespaces and publisher endpoints. None should be copied into `known-ads.txt` merely to increase test coverage.

A hostname may enter a positive advertising fixture only when the evidence record includes:

1. Exact FQDN and narrow intended scope.
2. Current, dated evidence of advertising delivery or ad-measurement behavior (for example, reproducible controlled app traffic or authoritative technical documentation).
3. Source attribution and exact observation provenance.
4. Confirmation that it is not merely a generic publisher, media, image CDN, login, telemetry, fraud-control or product dependency.
5. A repeatable test procedure and a review date.
6. An explicit confidence level and reviewer decision.

An unresolved hostname must remain unresolved. It must not be counted as a confirmed ad endpoint or used as a required blocking sentinel.

## 4. Recommended corpus structure

Before expanding the current plain-text sentinels, introduce a reviewed, machine-readable corpus (for example JSON Lines) with fields such as:

- `hostname`
- `classification`: `confirmed_ad`, `confirmed_tracker`, `unwanted_telemetry`, `threat`, `essential_service`, or `unresolved`
- `evidence_type`
- `evidence_url_or_artifact`
- `observed_at_utc`
- `reviewed_at_utc`
- `confidence`
- `service` and `affected_function`
- `source_rule_refs` and `source_snapshot_sha256`
- `expected_policy`: `blocked`, `allowed`, or `observe_only`
- `review_notes`

Do not put private user traffic, account identifiers, device identifiers, full unsanitized DNS logs or personal data in the public corpus. Use synthetic controlled test zones for DNS-client syntax tests.

## 5. Expansion plan

### Phase A — protect critical functions

Expand essential-service coverage with exact hosts and reproducible function-level tests, prioritizing:
- bank and payment login/authorization;
- carrier account, recharge and messaging;
- government identity and service portals;
- device/app updates and push;
- maps, navigation and ride-hailing;
- video/live playback and CDN;
- office cloud sync and document operations.

Each entry must be supported by a known service/function relationship. Do not guess hostnames from product names.

### Phase B — establish domestic advertising ground truth

Investigate the candidate clusters in the advertising review. Use controlled DNS capture with filtering on/off, repeatable app workflows and exact FQDN correlation. Add only independently verified endpoints to a positive fixture set. Keep ad-delivery and measurement classifications separate where the evidence supports that distinction.

### Phase C — separate privacy and security classes

Create separate reviewed sets for trackers, unwanted telemetry and threat domains. A tracker or telemetry endpoint is not automatically an advertising endpoint; a threat indicator needs threat-intelligence provenance and expiration/revalidation policy.

### Phase D — measure, do not overclaim

For every published metric, record:
- corpus revision and class counts;
- sample-selection method and denominators;
- date, region/network and resolver/client versions;
- exact NobleDNS release/source fingerprints;
- true-positive/false-positive definitions;
- unresolved and excluded entries;
- known limitations and confidence intervals where statistically appropriate.

Do not present a hand-curated convenience sample as representative of all Mainland apps or users.

## 6. Acceptance criteria

The corpus expansion is complete only when:
- every fixture has a classification and traceable evidence record;
- unresolved entries are excluded from pass/fail ground truth;
- block and exception precedence is tested against synthetic fixtures;
- essential and positive-blocking sentinels are tested in both direct and parent-domain coverage cases;
- changes to the corpus require review and a complete regression run;
- the README and quality policy describe exactly what the measurements do and do not prove.

## 7. Current decision

No new domain is promoted into either production subscription or the existing known-ad fixture set by this analysis. The immediate next task is to design and implement the evidence-backed corpus schema and validation tests on an isolated branch, then populate it only with verified records.
