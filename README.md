# NobleDNS

**One balanced edition · Mainland-oriented · Compatibility first**

NobleDNS is an independently maintained DNS blocklist for everyday use, designed with mainland China network conditions in mind. It focuses on a practical balance: blocking unwanted advertising and tracking while keeping legitimate websites, apps and essential services working.

We maintain **one balanced edition**—one subscription, one quality standard, one release line. No confusing collection of lite, aggressive or regional variants.

**中文介绍：[README.zh-CN.md](README.zh-CN.md)** · **Quality policy: [docs/QUALITY.md](docs/QUALITY.md)**

## Why NobleDNS

- **Mainland-use priorities.** Compatibility review gives particular attention to sign-in, payments, banking, messaging, push notifications, shopping, maps, video, software updates and public services.
- **Conservative blocking.** Prefer clear, appropriately scoped domain rules. Avoid broad blocks and speculative additions when evidence is weak.
- **Balanced protection.** Reduce advertising, tracking and unwanted telemetry without treating maximum block count as the goal.
- **One consistent edition.** All users receive the same maintained rule set and benefit from the same fixes.
- **Auditable maintenance.** Controlled upstream inputs, syntax-aware parsing, regression tests, source-drift checks and published build reports.

“Mainland-oriented” and “low false-positive” describe the project's design priorities. We work toward that goal through conservative rule scope, compatibility-focused review and reproducible correction—not through unsupported numerical promises.

## Current build at a glance

v1.0.3 baseline snapshot, verified **2026-11-12 (UTC)**.

- **303,625** unique blocking rules, plus **11** active upstream exceptions (**303,636** total subscription rules).
- **189,716** supported simple blocking rules parsed from AdGuard DNS Filter are retained in the merged set.
- **113,909** additional HaGeZi-only blocking rules are added relative to the AdGuard DNS Filter baseline.
- The merged output is the union of the two parsed source sets; unsupported or complex upstream syntax is excluded rather than guessed or rewritten.

These are build-manifest counts, not a claim that every raw upstream line is supported or that every listed domain has been individually reviewed. See the [manifest](dist/manifest.json) for source fingerprints and exact build metadata.

## Subscribe

**NobleDNS Balanced Edition — the only public subscription**

`https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt`

Add this URL as a custom DNS blocklist in a compatible filtering client. Keep the URL unchanged; validated builds update the contents at this address. The refresh schedule is controlled by your client.

**Legacy-compatible URL:** `https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/NobleDNS.txt` — maintained as a byte-identical mirror of the canonical subscription.

- [Open the current rule file](https://github.com/LucentDNS/NobleDNS/blob/main/dist/dns-filter.txt)
- [Open the legacy-compatible mirror](https://github.com/LucentDNS/NobleDNS/blob/main/NobleDNS.txt)
- [Build manifest](dist/manifest.json)
- [Latest validation report](dist/validation-report.txt)
- [Upstream badfilter directive audit](dist/badfilter-audit.csv)
- [Active upstream exceptions](dist/allowlist-active.txt)
- [Versioned releases](https://github.com/LucentDNS/NobleDNS/releases)

## Filtering scope

NobleDNS provides DNS-level blocking for advertising, tracking, telemetry and other unwanted domains represented by its configured sources. DNS filtering is one layer of protection; it cannot remove every ad, especially first-party ads, ads served from shared domains or content embedded directly in apps and media.

The main subscription contains blocking rules and the explicitly supported exception rules supplied by the upstream filters. Any domain appearing in the compiled subscription is included **as a DNS blocking target only**; its presence does not mean NobleDNS hosts, publishes, endorses, operates or distributes the associated website or its content. Supported upstream exceptions preserve the source's intended scope, including domain-and-subdomain exceptions (`@@||domain^|`) and exact-hostname exceptions (`@@|domain^|`). Unsupported exception patterns remain excluded and recorded in the parser-exclusion report.

## Sources and maintenance

The current build uses two established general-purpose upstream lists:

1. [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)
2. [HaGeZi Multi Normal](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt)

They provide broad DNS-filtering coverage; they are not mainland-China-specific datasets. NobleDNS applies its own source controls, supported-syntax handling, build validation and maintenance policies. The project is independent and is not affiliated with either upstream.

Our maintenance process is designed to keep the list dependable:

- Reject malformed or unsupported input rather than guessing at its meaning.
- Preserve supported rule semantics instead of silently broadening a rule.
- Check unexpected upstream changes and output integrity.
- Run regression tests and enforce the 500,000-rule ceiling.
- Keep validation reports and release artifacts available for inspection.
- Review compatibility reports and turn confirmed corrections into regression tests.

## Quality, compatibility and transparency

We take compatibility seriously and publish the methods used to assess it. The technical documentation records the current test scope, known syntax-verification work and the evidence needed before making measured effectiveness claims.

- [Quality and maintenance policy](docs/QUALITY.md)
- [DNS client compatibility test plan](docs/COMPATIBILITY-TEST-PLAN.md)
- [Single-edition policy](docs/EDITION-POLICY.md)
- [Validation report](dist/validation-report.txt)
- [Syntax inventory](dist/syntax-audit.json)
- [Third-party notices](THIRD-PARTY-NOTICES.md)

The project does not present build success as proof that every app has been tested, or claim a measured mainland false-positive rate without a representative test corpus. We prefer clear evidence and steady improvement over marketing claims.

## Feedback and corrections

If a website or app is affected, please report the exact hostname, affected function (such as sign-in, payment, push, playback or updates), DNS client/version and reproducible steps through [GitHub Issues](https://github.com/LucentDNS/NobleDNS/issues).

Reports comparing behavior with NobleDNS enabled and disabled under otherwise identical conditions are especially useful. Please remove personal information, account details, tokens and private data from logs. See the [feedback guide](docs/FEEDBACK.md).

## Build and license

The builder and regression tests use the Python standard library; Python 3.12 is required. See the [maintainer guide](docs/MAINTAINER-GUIDE.md) for reproducible local builds and release procedures.

NobleDNS project code is licensed under [GPL-3.0-only](LICENSE). Compiled rule data includes upstream-derived material and remains subject to applicable upstream licenses and third-party terms; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
