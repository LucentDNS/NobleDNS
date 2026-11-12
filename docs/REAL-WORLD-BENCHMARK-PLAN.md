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

The reviewed corpus has not yet been populated. A header-only template is provided at `tests/fixtures/reviewed-benchmark-corpus.template.csv`. Do not fill it with synthetic domains, unreviewed upstream entries or names inferred from their labels.

Build a versioned corpus with independently reviewed records:

| Class | Expected policy | Minimum evidence |
|---|---|---|
| Confirmed ad delivery | Block | Controlled request/traffic capture, vendor documentation or independent research; high confidence |
| Confirmed tracking/analytics | Block | Same; distinguish first-party functional telemetry from unwanted cross-site tracking |
| Confirmed unwanted telemetry | Block | Evidence of purpose, scope and user impact; do not classify crash reporting as advertising by default. Observe-only or unresolved items are excluded from scored rows |
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

The offline scorer in `tools/score_benchmark.py` validates this CSV schema, rejects explicitly expired or non-high-confidence records, refuses to score unsupported rule syntax, and writes SHA-256 plus byte-size identities for the exact rules file, corpus file and scorer source into every result artifact. Its `independent=true` field is an attestation, not cryptographic proof; each row also records a primary reviewer and a distinct independent reviewer. Threat records require an expiry date, and expired evidence is rejected. The scorer models only the syntax currently accepted by the published v1.0.3 parser: `||domain^` (domain and subdomains, with hostname-end boundary), `||domain` (hostname-start anchor without an end separator), and `@@||domain^` (exception). Leading-dot records are excluded by the current production parser; an open proposal to preserve them must not be treated as supported until authoritative semantics and client behavior are established. Other syntax is rejected rather than silently scored. This offline model is not a substitute for a real client or DNS query; comparator lists must be normalized to semantically equivalent supported forms with all exclusions disclosed before a fair score can be claimed.

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

## 7. Product readiness versus field-evidence maturity

The benchmark is a quality-improvement and evidence programme, **not a rule that blocks every public release until a large field study is complete**. NobleDNS should be useful and responsibly maintained at release time, based on the best available public evidence, source review, conservative policy, compatibility knowledge and reproducible internal checks. A release must not knowingly ship unresolved high-impact defects or unreviewed source imports merely because a benchmark is incomplete.

Before each release, apply the checks appropriate to the claim being made:
- Verify source identity, license/provenance, scope, update health and material changes.
- Review known conflicts against essential services and resolve or explicitly exclude risky additions.
- Validate parser semantics, output integrity, exceptions, subscription format and supported-client compatibility to the extent claimed.
- Run the project's existing regression suite and inspect new/changed rules; do not treat rule count or CI success as efficacy proof.
- Publish known limitations honestly and retain rollback capability.

The following are gates for stronger claims such as **field-tested mature**, **measured low false-positive**, or **competitively benchmarked**; they are not a reason to leave an otherwise responsibly prepared release indefinitely unpublished:
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
- The reviewed evidence corpus is not yet populated; only a header-only CSV template and an offline scorer exist.
- The real DNS client compatibility matrix remains NOT TESTED unless supported by linked, reproducible run evidence.
- No comprehensive mainland application/site task matrix has been completed.
- No comparative efficacy or performance score has been established.
- The rule-liveness observation fixture is empty; no live multi-vantage liveness conclusions exist.

Therefore, current evidence does not support claims that NobleDNS is fully field-tested, has a measured low false-positive rate, or is objectively superior to established lists. This does not by itself mean the published v1.0.3 release is a half-finished product; it means those stronger empirical claims remain unproven and must not be advertised as facts.

## 9. Reporting template

Every scored report should contain: executive summary and limitations; immutable list/corpus identities (version, commit, SHA-256); environment and exact client/resolver versions; corpus composition, evidence quality and sampling method; per-category TP, FP, FN, precision and recall; critical service task outcomes and severity; DNS latency, timeout, throughput, CPU and memory distributions; differences versus every comparator with confidence intervals where applicable; raw sanitized artifacts and reproduction steps; reviewer sign-off, unresolved questions and next test date.

The scorer's supported-rule parser and confusion-matrix calculations are covered by unit tests; it rejects leading-dot and malformed trailing-dot rule patterns to match the published parser's current behavior. Corpus hostnames may include one terminal DNS root dot, which is normalized before scoring; multiple terminal dots and non-ASCII hostnames are rejected. Every scored row must include two distinct reviewers, and threat evidence must have an expiry date. Its output must always be labeled as offline simulation. The corpus template contains no pre-approved hostnames.\n\nThis plan is a test protocol only. It does not change the public rule set, add candidate sources or authorize publication of benchmark claims.
