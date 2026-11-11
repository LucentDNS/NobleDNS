# NobleDNS

**Lightweight. Conservative. Auditable.**

NobleDNS is a conservative DNS blocklist build project based on a small, fixed set of upstream sources. Its purpose is to produce a lightweight, reviewable blocklist while preserving supported rule semantics and avoiding speculative rewrites.

> **Status: RC3 automation candidate — not production-qualified.**
>
> The current builder compiles only supported simple domain-anchor forms. Unsupported or complex filter syntax is excluded rather than approximated. Live DNS-client compatibility, real-world false-positive rate, and missed-block rate have not yet been established.

## Project goals

- Keep the rule set lightweight and within a strict 500,000-rule ceiling.
- Prefer stable, conservative blocking with low false-positive risk.
- Preserve rule semantics; never rewrite unsupported syntax into a guessed equivalent.
- Keep the main subscription block-only.
- Publish upstream exceptions separately for review; do not activate them as a global allowlist.
- Fail closed on malformed input, abnormal source drift, invalid output, duplicate output, or rule-count limit violations.
- Make builds auditable and reproducible from retained source snapshots.
- Publish only after automated validation succeeds.

## Upstream sources

The authoritative source configuration is [`config/sources.json`](config/sources.json).

Exactly two upstream sources are currently configured:

1. **AdGuard DNS Filter**
   <https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt>

2. **HaGeZi Multi Normal**
   <https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt>

Do not add, remove, or replace an upstream source without documenting the evaluation and reviewing the resulting rule changes.

## Current candidate baseline

The RC2.2 baseline, also used to verify the RC3 builder, contains:

| Item | Baseline |
|---|---:|
| Upstream sources | 2 |
| Compiled blocking rules | 301,975 |
| Maximum permitted rules | 500,000 |
| Release channel | candidate |
| Production qualification | Not qualified |

The baseline is a reproducibility reference, not a claim that every compiled rule has been validated against live DNS traffic.

See [`docs/RC2.2-BASELINE.md`](docs/RC2.2-BASELINE.md) for baseline details.

## Local build

Requirements:

- Python 3.12 recommended.
- Standard-library-only build and test execution.
- Network access for downloading upstream sources; alternatively, provide saved source snapshots for an offline build.

Run from the repository root in PowerShell:

```powershell
# Build from the configured upstream sources
py -3.12 .\update.py --out .\build-output

# Build offline from previously saved source snapshots
py -3.12 .\update.py `
  --input-dir .\audit-input `
  --out .\build-output

# Run regression tests
py -3.12 -m unittest discover -s tests -v
