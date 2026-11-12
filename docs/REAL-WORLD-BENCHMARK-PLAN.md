# Real-world effectiveness and compatibility benchmark plan

> Status: protocol and acceptance framework; **no real-world benchmark results have been collected yet**.
> This document does not change the production subscription or approve any new source.

## 1. Purpose

NobleDNS must be evaluated by what users experience, not by rule count, source reputation, build success or CI status. The goal is to establish whether the single balanced edition can compete with established DNS blocklists on useful blocking coverage while maintaining excellent compatibility.

The benchmark must answer four separate questions:
1. **Coverage:** Does the list block independently confirmed advertising, tracking, unwanted telemetry and threat domains?
2. **Compatibility:** Does it avoid blocking legitimate services and dependencies required for sign-in, payment, messaging, push, maps, video, downloads and updates?
3. **Client correctness:** Do supported DNS clients interpret every published rule form as intended?
4. **Operational cost:** What are the effects on latency, memory, CPU, query throughput, startup/list-load time and update reliability?

A result in one category must never be presented as proof in another. A successful parser test is not a coverage result; a high block percentage is not a quality result if essential services break.

## 2. Comparators and reproducibility

Run the same test corpus against, at minimum:
- NobleDNS Balanced (exact published commit and SHA-256).
- AdGuard DNS Filter (exact downloaded snapshot and SHA-256).
- HaGeZi Multi NORMAL (exact downloaded snapshot and SHA-256).
- OISD Big (exact downloaded snapshot and SHA-256), once snapshot and license/provenance metadata are recorded.

Additional lists may be added only when their current format, scope, provenance and test permissions are clear. Do not merge comparator data into NobleDNS.

For every run, preserve:
- Test date/time UTC, operator and test location/network.
- Exact client, client version, OS, device class and resolver configuration.
- Exact list URL, immutable source commit where available, downloaded-file SHA-256 and byte size.
- Corpus revision and SHA-256.
- IPv4/IPv6 state, DNS transport, cache state and repetition number.
- Raw per-hostname outcomes and sanitized logs.

Never compare different resolver providers, client versions, cache states or network paths and attribute the difference solely to the list. Run each list in isolation; do not stack lists for the primary comparison. Randomize run order and repeat each scenario at least three times.

## 3. Ground-truth corpus

The current `tests/fixtures/evidence-corpus.json` is intentionally empty. Do not fill it with synthetic domains, unreviewed upstream entries or names inferred from their labels.

Build a versioned corpus with independently reviewed records:

| Class | Expected policy | Minimum evidence |
|---|---|---|
| Confirmed ad delivery | Block | Controlled request/traffic capture, vendor documentation or independent research; high confidence |
| Confirmed tracking/analytics | Block | Same; distinguish first-party functional telemetry from unwanted cross-site tracking |
| Unwanted telemetry | Block or observe-only | Evidence of purpose, scope and user impact; do not classify crash reporting as advertising by default |
| Confirmed threat | Block | Reputable threat-intelligence evidence, timestamp, expiry and revalidation |
| Essential/legitimate service | Allow | Controlled successful use, vendor documentation or independent research |
| Unresolved | Observe only | Insufficient, conflicting or stale evidence |

Requirements:
- A source-list match alone is never independent ground truth.
- Keep provenance and classification evidence separate from the list being scored.
- Include positive and negative examples, including domains shared by legitimate and advertising functions.
- Record the exact affected function and hostname, not only the registrable domain.
- Review threat indicators frequently and expire stale records.
- Keep a blind holdout subset unavailable to the person tuning rules until an evaluation round is frozen.
- Never commit private traffic logs, identifiers, credentials or user-specific browsing histories.

The existing evidence-corpus validator is a starting point, not a substitute for expert review. Extend its schema only through separately tested changes.

## 4. Metrics

Report every metric with numerator, denominator, confidence interval where appropriate, date, corpus version and exclusions.

### 4.1 Blocking efficacy
For independently confirmed block-worthy hostnames:
- True positives (TP): correctly blocked.
- False negatives (FN): allowed or unresolved by the tested filter.
- Recall / coverage: TP / (TP + FN).

For all blocked decisions in the reviewed corpus:
- False positives (FP): legitimate/essential hostnames incorrectly blocked.
- Precision: TP / (TP + FP).

Report separately for ads, tracking, telemetry and threats. Never collapse categories into one headline score. Threat feeds require time-bounded ground truth; stale indicators must not inflate coverage.

### 4.2 Compatibility
Report critical-service false-positive count/rate, affected services/functions, login/payment/push/call/map/playback/download/update task success, page-load/application-task success relative to the same environment with filtering disabled, and severity/reproducibility of every failure.

A critical payment, banking, identity, messaging or system-update failure is a release blocker until explained and corrected. No confirmed critical-service false positive is acceptable in the release acceptance corpus.

### 4.3 Performance and resource use
On identical hardware and client versions, measure:
- DNS query latency p50, p95 and p99, cold-cache and warm-cache.
- Successful answer rate and timeout/SERVFAIL rate.
- Sustained query throughput and CPU utilization.
- Peak and steady-state memory attributable to the filter.
- Client startup, list download, parse/load and update duration.
- Subscription byte size and rule count.

Use the same query workload and resolver for every list. Separate upstream resolver latency from local rule-matching overhead. Repeat enough times to expose variance; publish raw samples, not only averages.

## 5. Test layers

### Layer A — Static and parser correctness
Keep syntax, normalization, duplicate, exception, IDNA, malformed-input and drift regression tests. Verify exact semantics on each claimed client version using the controlled `.test` zone in [COMPATIBILITY-TEST-PLAN.md](COMPATIBILITY-TEST-PLAN.md). A client is not verified merely because the format is accepted or a subscription downloads successfully.

### Layer B — Independent hostname corpus
Query each reviewed hostname against one isolated list at a time. Capture the exact DNS decision and matching rule. Confirm positive and negative controls resolve with filtering disabled. Repeat with cold and warm caches; distinguish NXDOMAIN, REFUSED, sinkhole and timeout. Score only records with current, independent evidence.

### Layer C — Real application and website tasks
Create a representative task matrix for mainland China and international everyday use. Include multiple operators/regions where available, IPv4 and IPv6, mobile and broadband networks.

At minimum cover:
- Banking, identity, payment and account login.
- Messaging, voice/video calls and push delivery.
- E-commerce, delivery and local services.
- Maps, transport and location search.
- Video, music, live streaming and CDN delivery.
- App stores, downloads, software/OS updates.
- Government, education and public-service portals.
- Common international websites and services.

For each task, record a deterministic success criterion, required hostname evidence, baseline result without filtering, result with each isolated list, logs and reproducibility. Do not mark an entire app as tested after checking only its home page.

### Layer D — Long-running stability
Run a controlled pilot for at least 7 consecutive days: repeated scheduled task checks; DNS timeout and SERVFAIL tracking; resolver failover and network switching; sleep/wake, Wi-Fi/mobile transitions and IPv4/IPv6 behavior; subscription refresh and rollback; memory/CPU observations and client crash/restart events.

A liveness NXDOMAIN observation is not a false-positive measurement and must not automatically remove a rule.

## 6. Sampling and anti-bias controls

- Stratify the corpus by service category, popularity, region, domain age and dependency type.
- Include high-traffic services and less popular but important public-interest services.
- Do not sample only from current upstream lists; that rewards lists for agreeing with themselves.
- Avoid selecting only domains known to be blocked by NobleDNS.
- Freeze corpus and list snapshots before each scored round.
- Have a second reviewer adjudicate disputed records and critical false positives.
- Publish missing data and exclusions; never silently discard failed tests.
- Use a separate discovery set for finding candidates and a holdout set for final scoring.

A small convenience sample is useful for regression testing but cannot support a claim of representative national performance.

## 7. Release gates

Minimum gates before NobleDNS may be described as a **field-tested mature balanced list**:
1. All published syntax forms have reproducible pass results on each explicitly supported client/version.
2. No unresolved critical false positive remains in the reviewed essential-service matrix.
3. The independent corpus has meaningful, category-stratified positive and negative samples, with a blind holdout and current evidence.
4. NobleDNS is compared head-to-head with named comparators using identical clients, resolvers, workloads and snapshots.
5. Coverage, precision, recall, critical compatibility and performance are all reported; no single metric hides a weakness in another.
6. A multi-network, multi-day pilot completes without unexplained critical breakage or material stability regression.
7. Every benchmark artifact is traceable to immutable snapshots and reproducible instructions.

Do not invent numerical pass thresholds before collecting a baseline. Establish a pre-registered threshold for each metric after a pilot, document why it is appropriate, and do not lower it after seeing an unfavorable result. Critical-service compatibility remains a zero-known-critical-failure gate.

## 8. Current evidence and honest status

At the time this plan is added:
- The automated regression corpus contains 72 essential-service hostnames and 20 known advertising-infrastructure hostnames; these are regression sentinels, not a representative independent benchmark.
- The evidence-backed corpus is empty.
- The real DNS client compatibility matrix remains NOT TESTED unless supported by linked, reproducible run evidence.
- No comprehensive mainland application/site task matrix has been completed.
- No comparative efficacy or performance score has been established.
- The rule-liveness observation fixture is empty; no live multi-vantage liveness conclusions exist.

Therefore NobleDNS must not yet be marketed as fully field-tested, proven low-false-positive or objectively superior to established lists.

## 9. Reporting template

Every scored report should contain: executive summary and limitations; immutable list/corpus identities (version, commit, SHA-256); environment and exact client/resolver versions; corpus composition, evidence quality and sampling method; per-category TP, FP, FN, precision and recall; critical service task outcomes and severity; DNS latency, timeout, throughput, CPU and memory distributions; differences versus every comparator with confidence intervals where applicable; raw sanitized artifacts and reproduction steps; reviewer sign-off, unresolved questions and next test date.

This plan is a test protocol only. It does not change the public rule set, add candidate sources or authorize publication of benchmark claims.
