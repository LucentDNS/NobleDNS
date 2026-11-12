# NobleDNS

**Lightweight. Conservative. Auditable.**

NobleDNS is a community-maintained DNS blocklist for everyday use. It combines established upstream sources to help block advertising, tracking, telemetry and other unwanted domains, with reproducible builds, preserved rule semantics and transparent maintenance.

NobleDNS is publicly maintained and intended for use with compatible DNS filtering clients. Rules are updated through automated builds, validation and ongoing maintenance.

## Subscribe

**Subscription URL**

`https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt`

Add this URL as a custom DNS blocklist in a client that supports the rule syntax used by NobleDNS. Keep this URL when subscribing; the file at this address is updated when a validated build is published. Refresh timing is controlled by your client.

- [View the current rule file](https://github.com/LucentDNS/NobleDNS/blob/main/dist/dns-filter.txt)
- [View the published build manifest](dist/manifest.json)
- [View the latest validation report](dist/validation-report.txt)

## Compatibility

NobleDNS is intended to provide effective DNS-level protection in everyday use while preserving normal website and application functionality.

The project aims to block advertising, tracking, telemetry and other unwanted domains without unnecessarily interfering with legitimate services, including sign-in, payment, messaging and push notifications. Use a DNS filtering client that supports the rule syntax in this list.

If you encounter a specific false positive or missed block, please report the affected hostname, site or app, client and version, and reproduction details through [GitHub Issues](https://github.com/LucentDNS/NobleDNS/issues). Reports help improve rule quality for everyone.

## What it does

- Combines a deliberately limited set of upstream DNS block rules.
- Keeps the main subscription block-only; upstream exceptions are published separately for review.
- Preserves supported rule syntax instead of guessing at semantic conversions.
- Rejects malformed input, unexpected source drift, invalid or duplicate output, and builds above the 500,000-rule ceiling.
- Publishes the current rule set and its validation reports after automated checks succeed.

## Upstream sources

Exactly two sources are currently configured in [config/sources.json](config/sources.json):

1. [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)
2. [HaGeZi Multi Normal](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt)

NobleDNS is an independent project and is not affiliated with or endorsed by either upstream.

## Quality and transparency

Rule count alone is not a measure of filtering quality. See:

- [Quality and acceptance policy](docs/QUALITY.md)
- [Current published manifest](dist/manifest.json)
- [Validation report](dist/validation-report.txt)
- [DNS syntax inventory](dist/syntax-audit.json)
- [Syntax compatibility review](dist/syntax-review.csv)
- [Parser exclusions](dist/parser-exclusions.csv)
- [Third-party notices](THIRD-PARTY-NOTICES.md)

The RC2.2 baseline documented in [docs/RC2.2-BASELINE.md](docs/RC2.2-BASELINE.md) is a historical reproducibility reference for a fixed pair of source snapshots. Its rule count is not the current published rule count.

## Feedback and rule corrections

Report suspected false positives, missed blocks or compatibility problems through [GitHub Issues](https://github.com/LucentDNS/NobleDNS/issues). Include the exact hostname, affected site or app, client and version, reproduction steps, and relevant sanitized DNS evidence.

Do not post personal identifiers, authentication tokens, account information or complete private DNS logs. See the [feedback and rule improvement guide](docs/FEEDBACK.md) before submitting a report.

## Build and test locally

Requirements:

- Python 3.12.
- Network access to retrieve upstream sources, or saved source snapshots for an offline build.
- The builder and regression tests use the Python standard library.

From the repository root:

```powershell
# Build from configured upstream sources
py -3.12 .\\update.py --out .\\build-output

# Build offline from saved source snapshots
py -3.12 .\\update.py --input-dir .\\audit-input --out .\\build-output

# Run regression tests
py -3.12 -m unittest discover -s tests -v
```

See the [maintainer guide](docs/MAINTAINER-GUIDE.md) for the complete maintenance, review and release procedure.

## License

The original NobleDNS project code is licensed under [GPL-3.0-only](LICENSE). Compiled rule data includes upstream-derived material and remains subject to applicable upstream licenses and third-party terms. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
