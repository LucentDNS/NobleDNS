# Comparator differential baseline — 2026-11-14

> Run: GitHub Actions #568, PR validation run. This is a frozen exact-rule differential, **not** an efficacy benchmark.
> NobleDNS: v1.0.7; subscription SHA-256: `e75877c27ec937deccb906c29a2a3278f57e8e0f9ec5470a381dd048a40d67a8`.
> Workflow: [run #568](https://github.com/LucentDNS/NobleDNS/actions/runs/43578645582) · [PR #76](https://github.com/LucentDNS/NobleDNS/pull/76).

## Snapshot identities

| List | Bytes | SHA-256 | Raw non-comment lines |
|---|---:|---|---:|
| NobleDNS v1.0.7 | 10,582,138 | `e75877c27ec937deccb906c29a2a3278f57e8e0f9ec5470a381dd048a40d67a8` | 457,457 |
| AdGuard DNS Filter | 4,679,830 | `c92cac0d119051ff734783996c9ca20cf54114503d3c8b989ee1cef5e72ac25d` | 191,470 |
| HaGeZi Multi PRO | 5,181,990 | `7668471dd94d03d962149b07a5e44c64b16c90af35bd5786524b5bb3ce40d1cc` | 226,839 |
| OISD Big | 5,150,193 | `70c051b9ac12b33fe6a42204fea301ed594143cead1e7085dbc22f20a860bd8a` | 228,042 |
| anti-AD AdGuard | 2,253,041 | `a419ebcda1c7df5582f06ace56391b5b9a6c1f2530747a1ace0062d0f1acdfe0` | 102,096 |

## Exact supported-syntax differential

Counts compare exact canonical rule strings accepted by NobleDNS's offline scorer. Exceptions are reported separately from blocking rules.

| Comparator | NobleDNS blocks | Comparator blocks | Exact shared | NobleDNS-only | Comparator-only | Comparator unsupported |
|---|---:|---:|---:|---:|---:|---:|
| AdGuard DNS Filter | 457,446 | 191,009 | 190,935 | 266,511 | 74 | 450 |
| HaGeZi Multi PRO | 457,446 | 226,838 | 226,838 | 230,608 | 0 | 1 (ABP header) |
| OISD Big | 457,446 | 228,041 | 190,353 | 267,093 | 37,688 | 1 (ABP header) |
| anti-AD AdGuard | 457,446 | 102,011 | 82,938 | 374,508 | 19,073 | 36 |

NobleDNS has 11 active exceptions, all matching the AdGuard DNS Filter snapshot exactly. HaGeZi PRO and OISD contain no supported exceptions in these snapshots. anti-AD contains 49 exceptions; none is automatically approved for NobleDNS.

## Findings and decisions

1. **HaGeZi Multi PRO is fully covered by exact rule identity.** All 226,838 supported PRO block rules appear in NobleDNS v1.0.7; the comparator-only count is zero. Adding HaGeZi Multi Normal or another Multi tier would be redundant. TIF Mini is a distinct threat-intelligence add-on and is not part of this general-list comparison.
2. **AdGuard DNS Filter is almost fully covered within the supported syntax subset.** Its 74 comparator-only strings are IP-literal rules, not hostnames. NobleDNS deliberately rejects IP literals as DNS hostname rules. Its 450 other unsupported lines include regex, leading-dot, wildcard and modifier forms that must not be flattened into guessed hostname blocks. The current AdGuard DNS Filter snapshot has 74 supported exact rules absent from NobleDNS, not a broad missing regional coverage gap.
3. **OISD Big has 37,688 exact supported rules absent from NobleDNS.** This is a discovery queue, not a bulk-import recommendation. Adding all of them would consume most of the remaining 42,543-rule headroom before any future source growth, and exact presence in OISD does not independently prove safety for NobleDNS's user base.
4. **anti-AD AdGuard has 19,073 exact supported rules absent from NobleDNS.** These are also discovery candidates only. anti-AD has 36 unsupported lines, including broad/dynamic wildcard patterns, and its 49 exceptions are not portable approvals.
5. **The current production ceiling remains 500,000 rules.** NobleDNS contains 457,446 blocking rules plus 11 active exceptions (457,457 total), leaving 42,543 subscription slots. The remaining space is not a target to fill.
6. **The comparator output is a syntax inventory, not a quality score.** It cannot establish true-positive rate, false-positive rate, real-world coverage, app compatibility, latency or resource use.

The scheduled comparator tool downloads immutable snapshots for each run, records their SHA-256 and byte sizes, and refuses to silently normalize unsupported syntax. The complete machine-readable report and downloaded snapshots are retained in the GitHub Actions artifact for the run.

## Limits

- Exact string overlap does not establish semantic equivalence. Different supported patterns can match the same hostname, and the comparator does not prove actual DNS-client behavior.
- Unsupported lines are counted and examples retained; they are not evaluated.
- Moving URLs can change between runs; the byte size and SHA-256 above identify only this run's snapshots.
- The independent reviewed hostname corpus is still insufficient to support a representative precision/recall or real-world compatibility claim.
- More unique rules can increase both coverage and breakage risk. Every proposed production addition still needs provenance, evidence, scope assessment and regression tests.

## Reproduction

The daily workflow runs `tools/comparator_differential.py` after the production build. The full report is `comparator-differential.json` in the [run #568 build-audit artifact](https://github.com/LucentDNS/NobleDNS/actions/runs/43578645582). The AdGuard Chinese audit is documented separately in [ADGUARD-CHINESE-DNS-AUDIT.md](ADGUARD-CHINESE-DNS-AUDIT.md).
