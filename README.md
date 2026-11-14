# NobleDNS

**One balanced edition · Conservative filtering · Compatibility first**

NobleDNS is an independently maintained DNS blocklist for everyday use, with mainland China network conditions as an important design consideration. It aims to reduce advertising, tracking and other unwanted DNS requests while minimizing disruption to legitimate websites, apps and services.

We maintain **one public edition, one subscription and one consistent rule policy**.

## Subscribe

**NobleDNS Balanced Edition — the only official subscription**

`https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt`

Add this URL to a client that supports AdGuard DNS filtering rules. Keep the URL unchanged; validated builds are published here. The client's own refresh settings determine when updates are downloaded.

Legacy compatibility URL: `https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/NobleDNS.txt`

## Our priorities

- **Measured blocking:** rule scope and potential impact matter more than raw rule counts.
- **Compatibility first:** sign-in, payments, banking, communications, push notifications, maps, video and software updates are important review areas.
- **Transparent sources:** upstreams, build manifests, syntax audits and parser exclusions are published.
- **Automated maintenance:** sources are refreshed and builds are checked regularly, with safeguards for unusual changes.

DNS filtering operates at the hostname-resolution layer. It cannot block every ad or replace cosmetic filtering, URL parameter removal or cookie-notice handling.

“Mainland-oriented” and “compatibility first” describe project priorities; they do not mean every mainland website and app has been tested. We do not claim a measured real-world blocking or false-positive rate without an independent, representative benchmark.

## Sources

The current build combines four sources:

1. [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt) — general DNS advertising and tracking protection.
2. [HaGeZi Multi Normal](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt) — balanced general-purpose rules.
3. [HaGeZi Multi PRO](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt) — broader coverage, retained alongside Normal so Normal-only rules are not lost.
4. [AWAvenue Ads Rule — Ads-only variant](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Adguard-Only.Ads.txt) — focused advertising coverage.

The compiler includes only explicitly supported syntax. Unsupported or ambiguous input is recorded and excluded rather than guessed or rewritten. The 11 inherited upstream exceptions currently in the subscription remain pending review; their presence does not mean NobleDNS has independently approved them. See the [exception review register](data/exception-review.csv).

Rule counts, upstream reputation and successful compilation do not by themselves prove that a rule is effective, necessary or safe. NobleDNS is independently maintained and is not affiliated with or endorsed by its upstream projects.

## How it complements AdGuard

NobleDNS is a DNS-layer complement, not a replacement for AdGuard Base, language filters, tracking protection, URL Tracking, Annoyances or cosmetic rules. DNS rules cannot hide page elements, remove URL parameters, handle cookie notices or rewrite page content.

We avoid turning page-level rules into broad hostname blocks and handle shared infrastructure for sign-in, payments, identity, push, CDNs and updates conservatively. See the [AdGuard complementarity and compatibility policy](docs/ADGUARD-COMPATIBILITY.md).

## Build transparency

These generated files document the current build:

- [Official DNS subscription](dist/dns-filter.txt)
- [Build manifest](dist/manifest.json) — source fingerprints, rule counts and build metadata.
- [Validation report](dist/validation-report.txt) — automated checks.
- [Syntax audit](dist/syntax-audit.json) — supported syntax inventory.
- [Parser exclusions](dist/parser-exclusions.csv) — excluded source lines and reasons.
- [Active exceptions](dist/allowlist-active.txt) — exceptions present in the subscription.

The project enforces a 500,000-rule ceiling and runs source-change checks and automated regression tests. These controls reduce maintenance risk; they do not replace real-device testing or an independent effectiveness benchmark.

## Report a problem

Report problems through [GitHub Issues](https://github.com/LucentDNS/NobleDNS/issues). Include the exact hostname, affected feature, DNS client and version, reproducible steps, and—where possible—a comparison with NobleDNS enabled and disabled while other settings remain unchanged.

Remove account details, tokens and other personal information from logs before sharing. See the [feedback guide](docs/FEEDBACK.md).

## Documentation

[Security](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Quality policy](docs/QUALITY.md) · [Compatibility test plan](docs/COMPATIBILITY-TEST-PLAN.md) · [Real-world benchmark protocol](docs/REAL-WORLD-BENCHMARK-PLAN.md) · [Single-edition policy](docs/EDITION-POLICY.md) · [Third-party notices and licenses](THIRD-PARTY-NOTICES.md)

## License

Project code is licensed under [GPL-3.0-only](LICENSE). Compiled rules contain upstream-derived material and remain subject to applicable upstream licenses and third-party terms. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

A domain's presence in the subscription identifies it only as a DNS filtering target; it is not an allegation against or endorsement of the associated website or operator.

---

The builder and regression tests use the Python standard library. Python 3.12 is required for maintenance; see the [maintainer guide](docs/MAINTAINER-GUIDE.md).
