# Comparator differential baseline — 2026-11-14

> Run: GitHub Actions #578, PR validation run. This is a frozen exact-rule differential, **not** an efficacy benchmark.
> NobleDNS: v1.0.7; subscription SHA-256: `635d5fcab5605459f5d1df59911de26dde5e6f218b2ce5acd9ed812e03cece47`.
> Workflow: [run #578](https://github.com/LucentDNS/NobleDNS/actions/runs/43579323077) · [PR #76](https://github.com/LucentDNS/NobleDNS/pull/76).

## Snapshot identities

| List | Bytes | SHA-256 | Raw non-comment lines |
|---|---:|---|---:|
| NobleDNS v1.0.7 | 10,585,030 | `635d5fcab5605459f5d1df59911de26dde5e6f218b2ce5acd9ed812e03cece47` | 457,508 |
| AdGuard DNS Filter | 4,679,830 | `c92cac0d119051ff734783996c9ca20cf54114503d3c8b989ee1cef5e72ac25d` | 191,470 |
| HaGeZi Multi PRO | 5,206,879 | `5059c6cd741c4129ef57b51a39cddeb6d4187e6ed4c32cc84200ece11f2fa083` | 227,849 |
| OISD Big | 5,150,561 | `6e19e0e4546e53b7571719b66bb09f10f39d18b50699d48513265e5e5cc52fcf` | 228,059 |
| anti-AD AdGuard | 2,253,041 | `a419ebcda1c7df5582f06ace56391b5b9a6c1f2530747a1ace0062d0f1acdfe0` | 102,096 |

## Exact supported-syntax differential

Counts compare exact canonical rule strings accepted by NobleDNS's offline scorer. Exceptions are reported separately from blocking rules.

| Comparator | NobleDNS blocks | Comparator blocks | Exact shared | NobleDNS-only | Comparator-only | Comparator unsupported |
|---|---:|---:|---:|---:|---:|---:|
| AdGuard DNS Filter | 457,497 | 190,935 | 190,935 | 266,562 | 0 | 524 |
| HaGeZi Multi PRO | 457,497 | 227,848 | 227,848 | 229,649 | 0 | 1 (ABP header) |
| OISD Big | 457,497 | 228,058 | 190,477 | 267,020 | 37,581 | 1 (ABP header) |
| anti-AD AdGuard | 457,497 | 102,011 | 82,943 | 374,554 | 19,068 | 36 |

NobleDNS has 11 active exceptions, all matching the AdGuard DNS Filter snapshot exactly. HaGeZi PRO and OISD contain no supported exceptions in these snapshots. anti-AD contains 49 exceptions; none is automatically approved for NobleDNS.

## Findings and decisions

1. **HaGeZi Multi PRO is fully covered by exact rule identity.** All 227,848 supported PRO block rules appear in NobleDNS v1.0.7; the comparator-only count is zero. Adding HaGeZi Multi Normal or another Multi tier would be redundant. TIF Mini is a distinct threat-intelligence add-on and is not part of this general-list comparison.
2. **AdGuard DNS Filter's hostname-rule subset is fully covered.** After aligning the benchmark scorer with the production compiler, its comparator-only count is zero. The 524 excluded lines comprise 74 IP-literal rules (not DNS hostnames) and 450 other unsupported forms, including regex, leading-dot, wildcard and modifier syntax. These must not be flattened into guessed hostname blocks.
3. **OISD Big has 37,581 exact supported rules absent from NobleDNS.** This is a discovery queue, not a bulk-import recommendation. Adding all of them would consume about 88.4% of the remaining 42,492-rule headroom before any future source growth, and exact presence in OISD does not independently prove safety for NobleDNS's user base.
4. **anti-AD AdGuard has 19,068 exact supported rules absent from NobleDNS.** These are also discovery candidates only. anti-AD has 36 unsupported lines, including broad/dynamic wildcard patterns, and its 49 exceptions are not portable approvals.
5. **The current production ceiling remains 500,000 rules.** NobleDNS contains 457,497 blocking rules plus 11 active exceptions (457,508 total), leaving 42,492 subscription slots. The remaining space is not a target to fill.
6. **The comparator output is a syntax inventory, not a quality score.** It cannot establish true-positive rate, false-positive rate, real-world coverage, app compatibility, latency or resource use.

The scheduled comparator tool downloads immutable snapshots for each run, records their SHA-256 and byte sizes, and refuses to silently normalize unsupported syntax. The complete machine-readable report and downloaded snapshots are retained in the GitHub Actions artifact for the run.

## Limits

- Exact string overlap does not establish semantic equivalence. Different supported patterns can match the same hostname, and the comparator does not prove actual DNS-client behavior.
- Unsupported lines are counted and examples retained; they are not evaluated.
- Moving URLs can change between runs; the byte size and SHA-256 above identify only this run's snapshots.
- The independent reviewed hostname corpus is still insufficient to support a representative precision/recall or real-world compatibility claim.
- More unique rules can increase both coverage and breakage risk. Every proposed production addition still needs provenance, evidence, scope assessment and regression tests.

## Reproduction

The daily workflow runs `tools/comparator_differential.py` after the production build. The full report is `comparator-differential.json` in the [run #575 build-audit artifact](https://github.com/LucentDNS/NobleDNS/actions/runs/43579150459). The AdGuard Chinese audit is documented separately in [ADGUARD-CHINESE-DNS-AUDIT.md](ADGUARD-CHINESE-DNS-AUDIT.md).
