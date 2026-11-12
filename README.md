# NobleDNS

**One balanced edition. Mainland-oriented. Conservative by design.**

NobleDNS is an independently maintained DNS blocklist designed for everyday use, with mainland China network compatibility as a primary design consideration. It maintains **one public balanced edition** rather than separate aggressive, strict, or regional variants.

The project prioritizes conservative source selection, compatibility review, and reproducible maintenance. The current compiler combines supported blocking rules from the configured upstream snapshots; it does not mean every individual upstream entry has been manually verified against mainland services. Its aim is to reduce advertising and tracking at the DNS layer without needlessly disrupting legitimate websites, apps, and essential online services.

**中文说明：[README.zh-CN.md](README.zh-CN.md)** · **Edition policy: [docs/EDITION-POLICY.md](docs/EDITION-POLICY.md)**

> **Important quality note:** “Mainland-oriented” and “low false-positive” describe the project's design priorities, not a statistically proven result. A measured mainland false-positive rate and a comprehensive domestic app/site compatibility matrix are not yet available. We publish evidence and limitations rather than making guarantees we cannot substantiate.

## The single balanced edition

NobleDNS intentionally publishes one main subscription:

- **Compatibility before maximum blocking:** avoid broad or speculative blocks when evidence is weak.
- **Conservative rule acceptance:** prefer clear DNS hostname rules; do not silently convert complex syntax into broader blocks.
- **Mainland-use awareness:** treat sign-in, payment, banking, messaging, push, shopping, maps, video, CDN, software updates and public-service access as important compatibility areas during review.
- **Balanced coverage:** combine advertising and tracking protection with a restrained rule scope and bounded resource use.
- **One maintained result:** no separate “lite”, “pro”, “aggressive” or country-specific editions that fragment testing and maintenance.

This is a policy commitment, not a claim that every listed service has already been tested. See the [single-edition policy](docs/EDITION-POLICY.md) and [quality policy](docs/QUALITY.md).

## Subscribe

**Main subscription URL**

https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt

Add this URL as a custom DNS blocklist in a client that supports the rule syntax used by NobleDNS. Keep this URL when subscribing; the file at this address is updated when a validated build is published. Refresh timing is controlled by your client.

- [View the current rule file](https://github.com/LucentDNS/NobleDNS/blob/main/dist/dns-filter.txt)
- [View the published build manifest](dist/manifest.json)
- [View the latest validation report](dist/validation-report.txt)
- [View official versioned releases](https://github.com/LucentDNS/NobleDNS/releases)

## What it blocks

The main list is a DNS-level blocklist intended to help block advertising, tracking, telemetry and other unwanted domains represented by its approved upstream sources. DNS filtering cannot remove every form of advertising, including first-party ads, content served from shared domains, or ads embedded directly in apps and media.

The main subscription is block-only. Upstream exception rules are kept separately for review and are not silently applied as allow rules.

## Upstream sources

Exactly two sources are currently configured in [config/sources.json](config/sources.json):

1. [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)
2. [HaGeZi Multi Normal](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt)

These are established general-purpose upstream lists; they are **not mainland-China-specific lists**. NobleDNS applies source-level controls, syntax constraints and build validation, but does not manually re-classify every upstream rule. It does not claim affiliation with or endorsement by either upstream.

## Test coverage and limitations

Automated regression tests cover the builder's supported parsing and validation behavior. They do not establish real-world blocking effectiveness, a measured false-positive rate, or compatibility with every DNS filtering client. NobleDNS does not currently publish a live-device compatibility matrix or claim that every website and app has been tested.

The current evidence gaps include:
- No measured true-positive or false-positive rate based on a representative, independently reviewed mainland-use test corpus.
- No completed live DNS integration matrix for AdGuard for Android, AdGuard Home and other clients.
- No comprehensive, continuously maintained website/app compatibility matrix.
- 69 upstream hostname-anchor rules without an explicit end separator remain flagged for targeted client verification.

These are open verification tasks, not evidence that the rules are defective. See [quality and maintenance policy](docs/QUALITY.md) and the [DNS client compatibility test plan](docs/COMPATIBILITY-TEST-PLAN.md).

## What it does

- Maintains one balanced public DNS subscription.
- Combines a deliberately limited set of approved upstream DNS block rules.
- Preserves supported rule syntax instead of guessing at semantic conversions.
- Rejects malformed input, unexpected source drift, invalid or duplicate output, and builds above the 500,000-rule ceiling.
- Publishes the current rule set and its validation reports after automated checks succeed.

## Quality and transparency

Rule count alone is not a measure of filtering quality. See:

- [Single-edition policy](docs/EDITION-POLICY.md)
- [Quality and acceptance policy](docs/QUALITY.md)
- [DNS client compatibility test plan](docs/COMPATIBILITY-TEST-PLAN.md)
- [Current published manifest](dist/manifest.json)
- [Validation report](dist/validation-report.txt)
- [DNS syntax inventory](dist/syntax-audit.json)
- [Syntax compatibility review](dist/syntax-review.csv)
- [Parser exclusions](dist/parser-exclusions.csv)
- [Third-party notices](THIRD-PARTY-NOTICES.md)

The RC2.2 baseline documented in [docs/RC2.2-BASELINE.md](docs/RC2.2-BASELINE.md) is a historical reproducibility reference for a fixed pair of source snapshots. Its rule count is not the current published rule count.

## Feedback and rule corrections

Report suspected false positives, missed blocks or compatibility problems through [GitHub Issues](https://github.com/LucentDNS/NobleDNS/issues). Include the exact hostname, affected site or app, client and version, reproduction details and relevant sanitized DNS evidence.

Domestic-service compatibility reports are especially useful when they identify the exact failing feature (for example, sign-in, payment, push, playback or update delivery) and can be reproduced with NobleDNS enabled and disabled under otherwise identical conditions.

Do not post personal identifiers, authentication tokens, account information or complete private DNS logs. See the [feedback and rule improvement guide](docs/FEEDBACK.md) before submitting a report.

## Build and test locally

Requirements: Python 3.12. Network access is needed to retrieve upstream sources, unless saved source snapshots are used for an offline build. The builder and regression tests use the Python standard library.

See the [maintainer guide](docs/MAINTAINER-GUIDE.md) for the complete maintenance, review and release procedure.

## License

The original NobleDNS project code is licensed under [GPL-3.0-only](LICENSE). Compiled rule data includes upstream-derived material and remains subject to applicable upstream licenses and third-party terms. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
