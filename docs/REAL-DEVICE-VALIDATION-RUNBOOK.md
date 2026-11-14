# NobleDNS real-device compatibility validation runbook

> Purpose: collect reproducible, task-level evidence for the published DNS subscription.
> This is a test procedure and blank record template, not a claim that any device test has passed.
> Do not change production block/allow rules from an unrepeatable observation.

## 1. Known reference environment

The project maintainer's previously recorded reference handset is iQOO Z10 Turbo+ (Dimensity 9400+, OriginOS 5), with AdGuard for Android 4.15.1, non-root operation and HTTPS filtering enabled. Reconfirm the installed app, OS build, resolver and filter state immediately before each run; do not assume these historical values are still current.

Record:
- Date/time with timezone; physical region and network operator (Wi-Fi broadband or mobile data).
- Device model, Android/OriginOS build, AdGuard app version and filtering mode.
- Resolver product, endpoint, transport (DoH/DoT/UDP), IPv4/IPv6 state.
- NobleDNS release/commit, exact subscription URL, downloaded file SHA-256 and byte size.
- Other enabled DNS/content filters, custom rules and allowlists. For the primary comparison, disable all other blocklists and custom rules.
- App name, app version/build, account state and relevant feature flags.

Never upload account identifiers, tokens, full URLs containing secrets, private browsing history or unredacted DNS logs.

## 2. Paired A/B procedure

For each application task, perform the same sequence in two conditions:

**A — Baseline:** NobleDNS disabled; keep the same resolver, network, device, app version and all other settings. Clear the app's local task state only when safe and record any cache clearing. Complete the task twice and record the outcome.

**B — NobleDNS:** enable only the exact NobleDNS subscription under test. Confirm the subscription downloaded and parsed. Flush the DNS cache using the supported client controls or restart the app/device consistently. Repeat the identical task twice.

Alternate A/B order on a later repetition to reduce order bias. Do not change resolver providers between A and B. Repeat on Wi-Fi and mobile data when available. A single success is not sufficient to clear a suspected intermittent issue.

## 3. Evidence capture

For every suspected failure, capture:
1. Exact task step and timestamp.
2. Expected result and observed result, including error text or screenshot with personal information removed.
3. Exact queried hostname from AdGuard DNS request log.
4. Exact matched NobleDNS rule and whether the decision was blocked, allowed, rewritten or timed out.
5. Whether the hostname resolves and the task succeeds with NobleDNS disabled.
6. Repeat count and whether the same hostname/rule reproduces the failure.
7. Any CNAME chain or related hostname only if the client log or controlled DNS observation exposes it.

A query occurring near a failure is correlation, not proof. Attribute the failure to a rule only when the exact hostname is matched by that rule, the baseline succeeds, the filtered condition fails reproducibly, and allowing that exact hostname restores the task without changing unrelated variables.

## 4. Priority task matrix

### P0 — investigate first
- **CapCut:** cold launch; signup; login; profile/account; open project; edit; upload/import; export; playback/share. The current lead is `||mssdk.capcutapi.us`; do not assume it is the only relevant hostname.
- **Huawei component:** identify whether the exact HiViewTunnel component exists on the tested device and whether the relevant user-experience/diagnostics setting is enabled. Test system stability, account/device services, diagnostics and normal network functions. Do not generalize one Huawei model's result to all Huawei devices.
- **TeraBox:** cold launch; login; browse files; preview; upload; download; share; widget/static UI. The current lead is `||global-staticplat.cdn.bcebos.com`; distinguish static assets from advertising behavior.

### P1 — critical everyday functions
- Banking and payment: app launch, login, identity verification, balance/query, payment confirmation (never make a real payment solely for testing).
- Messaging and communications: login, send/receive, voice/video call setup, push delivery.
- Telecom and system: carrier account, SMS/OTP receipt, app store, app download, OS/system update check.
- Maps and transport: search, route calculation, map tiles, location permission flow.
- Video/music: search, playback start, sustained playback, comments/account where relevant.
- E-commerce and delivery: login, search, cart, checkout page (stop before real order/payment).

### P2 — broader compatibility
- Government, education and public-service portals.
- Common international sites and services.
- App cold start, background/foreground transitions, sleep/wake and Wi-Fi/mobile network switching.

## 5. Decision rules

- **Confirmed false positive:** paired baseline succeeds; NobleDNS condition reproducibly fails; exact blocking rule is captured; allowing that exact hostname restores the same task; evidence is independently reviewed.
- **Likely false positive:** strong paired evidence exists but exact rule attribution or independent reproduction is incomplete. Keep unresolved; do not silently change production.
- **Not a false positive:** task fails in baseline too, or the hostname is not blocked by NobleDNS, or the failure cannot be reproduced under controlled conditions.
- **Unresolved/mixed-use:** hostname supports both optional telemetry/ads and a functional dependency, or evidence conflicts. Prefer narrow scope and assess whether the task impact justifies an exception/removal.
- **Cleared for this test only:** no failure in the named tasks, app version, device, region and network. Never convert this into a universal safety claim.

Any confirmed banking, identity, payment, messaging, carrier, system-update or device-management failure is a release-blocking investigation until resolved. Do not automatically add a broad exception; exceptions can weaken protection beyond the observed task.

## 6. Reporting

Store one row per hostname-rule-task observation in the accompanying CSV template. Preserve sanitized evidence references and exact versions. Keep discovery leads separate from confirmed classifications. A hostname is not "safe" merely because it did not appear in a short test; absence of a query is not evidence of absence of dependency.

A review is complete only when the primary reviewer records evidence and a distinct independent reviewer adjudicates the decision. If the maintainer is the only available tester, record independent review as pending rather than self-attesting.

## 7. Current limitation

The assistant can inspect repository evidence, prepare test procedures, analyze exported/sanitized logs and implement repository changes. It cannot remotely operate the handset or observe private app sessions. Device-side outcomes must be supplied by the operator before they can be reported as tested.
