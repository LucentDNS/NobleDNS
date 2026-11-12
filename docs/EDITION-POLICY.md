# Single-edition policy

## Product definition

NobleDNS publishes one public product: the **NobleDNS Balanced Edition**.

It is designed for everyday DNS filtering, with mainland China network compatibility as a primary consideration. The edition balances advertising and tracking protection, legitimate service availability, rule scope, runtime cost and maintainability.

This policy does not claim that NobleDNS has already achieved a measured low false-positive rate across mainland websites and apps. Such a claim requires reproducible evidence and a representative reviewed corpus.

## Why one edition

A single edition gives the project one consistent source approval process, rule acceptance standard, compatibility test matrix, issue triage queue, release artifact and rollback target.

Multiple public variants would multiply testing and support obligations before the project has sufficient real-world evidence and maintenance capacity.

## Design principles

1. Compatibility takes priority over maximum blocking volume.
2. Rule additions require source provenance and a defensible classification.
3. Prefer narrow hostname scope over broad parent-domain blocks.
4. Preserve supported source syntax; do not invent semantic equivalence.
5. Preserve only simple, supported upstream exceptions (`@@||domain^`) in the main subscription; keep complex or unsupported exceptions excluded. Project-authored allowlist additions require independent evidence, narrow scope and cross-source precedence tests.
6. Reject unexplained source drift and invalid build output.
7. Publish limitations and test evidence alongside the subscription.

## Mainland-use review priorities

When triaging compatibility reports and building a future reviewed corpus, prioritize account registration and sign-in; banking and payment; messaging, calls and push notifications; e-commerce and delivery; maps, navigation and travel; video, music and CDNs; app stores and update services; government, education and other public-service portals.

These are review categories, not a claim that every service has been tested. A report should identify the exact hostname and the affected user-visible function.

## Source policy

The configured AdGuard DNS Filter and HaGeZi Multi Normal sources are general-purpose upstream lists, not mainland-China-specific datasets. Their inclusion does not mean their maintainers have tested or endorsed NobleDNS's mainland compatibility goals.

Before adding or replacing a source, review purpose and category coverage; license and third-party input terms; syntax and compiler support; overlap and incremental value; parent-domain and shared-infrastructure risk; update cadence and change behavior; and reproducible evidence from representative test cases.

Do not add a source solely to increase rule count or advertise broader coverage.

## Evidence required for quality claims

Before publishing a measured low-false-positive claim, maintain a reviewed corpus that distinguishes confirmed advertising/tracking, confirmed unwanted telemetry, confirmed malicious or threat infrastructure, legitimate or essential service, and unresolved or disputed entries.

Each record should include evidence, provenance, review date, confidence, affected service/function and regression coverage where applicable. Unresolved records must not be counted as confirmed blocks or confirmed false positives.

Any published measurement must state the corpus revision, sample size, sampling method, client and resolver versions, test date, denominator and known limitations. Do not extrapolate a small convenience sample to all mainland users.

## Change control

For every confirmed false positive:
1. Reproduce with NobleDNS enabled and disabled while holding other network/client settings constant.
2. Verify the queried hostname and matching rule.
3. Rule out resolver, routing, TLS, application and upstream-service failures.
4. Assess whether the block is too broad or the hostname is genuinely shared with a legitimate service.
5. Make the narrowest evidence-supported correction.
6. Add a regression test and document the change.
7. Run the full validation suite before publication.

Do not add broad allowlist exceptions without understanding their scope and side effects.

## Version policy

The public subscription is the single balanced edition. Do not create separate lite, pro, strict, aggressive, regional or app-specific variants without a documented policy review, evidence of user need and demonstrated maintenance capacity.
