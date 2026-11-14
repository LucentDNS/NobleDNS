# Comparator differential baseline — 2026-11-14

> Run: GitHub Actions #537, PR validation run. This is a frozen initial rule-set differential, not an efficacy benchmark.
> NobleDNS subscription SHA-256: `e5a554c526e2e77db8dc4b875cf4066dd9e4a0985debc0dbd11a7dc93cbd5479`.

## Snapshot identities

| List | URL | Bytes | SHA-256 | Raw non-comment lines |
|---|---|---:|---|---:|
| NobleDNS v1.0.4 | [main subscription](https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt) | 7,369,306 | `e5a554c526e2e77db8dc4b875cf4066dd9e4a0985debc0dbd11a7dc93cbd5479` | 306,835 |
| AdGuard DNS Filter | [source](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt) | 4,678,883 | `0ab3e6393db16f26343dc0cd66060366418b3c6713fd4639e06ff11a38b49174` | 191,429 |
| HaGeZi Multi PRO | [source](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt) | 5,181,990 | `7668471dd94d03d962149b07a5e44c64b16c90af35bd5786524b5bb3ce40d1cc` | 226,839 |
| OISD Big | [source](https://big.oisd.nl/) | 5,149,246 | `979fa2ff7241574ecea8325a47f080dc38b12c2d31cb121d55413981718be6cb` | 228,004 |
| anti-AD AdGuard | [source](https://anti-ad.net/adguard.txt) | 2,253,041 | `a419ebcda1c7df5582f06ace56391b5b9a6c1f2530747a1ace0062d0f1acdfe0` | 102,096 |

## Exact supported-syntax differential

Counts below compare exact rule strings accepted by the current offline scorer. Exceptions are reported separately from blocking rules.

| Comparator | NobleDNS blocks | Comparator blocks | Exact shared | NobleDNS-only | Comparator-only | Comparator unsupported |
|---|---:|---:|---:|---:|---:|---:|
| AdGuard DNS Filter | 306,824 | 190,968 | 190,894 | 115,930 | 74 | 450 |
| HaGeZi Multi PRO | 306,824 | 226,838 | 183,403 | 123,421 | 43,435 | 1 (ABP header) |
| OISD Big | 306,824 | 228,003 | 93,624 | 213,200 | 134,379 | 1 (ABP header) |
| anti-AD AdGuard | 306,824 | 102,011 | 81,315 | 225,509 | 20,696 | 36 |

All 11 NobleDNS active exceptions exactly matched the AdGuard DNS Filter snapshot. The comparator snapshot contained 11 AdGuard exceptions, 0 HaGeZi PRO exceptions, 0 OISD exceptions and 49 anti-AD exceptions; anti-AD's 49 are not automatically approved for NobleDNS.

## Immediate findings and action

1. **HaGeZi Multi PRO is the clearest immediate coverage gap.** There are 43,435 supported exact block rules in the PRO snapshot that are not present in NobleDNS v1.0.4. A source-level preview found that adding PRO while retaining the existing sources would remain below the 500,000-rule ceiling by simple exact-set arithmetic; however, a production build, license/provenance review, compatibility regression and explicit large-change review are still required. Do not infer that all 43,435 are safe to add solely from upstream inclusion.
2. **AdGuard DNS Filter is very close by exact rule identity.** The current snapshot has 74 supported exact block rules absent from NobleDNS. Its 450 unsupported lines include regex rules, `$badfilter`, leading-dot records and other syntax outside the current DNS hostname compiler. Those must not be silently rewritten.
3. **OISD Big and anti-AD have substantial independent deltas.** Their exclusive counts are discovery queues, not instructions to import every rule. The anti-AD parser currently excludes 36 lines, including dynamic-suffix and broad wildcard patterns. These require semantic review before any parser expansion.
4. Preserve each run's downloaded snapshots and report so changes can be reproduced and audited.

## Limitations

- Exact text overlap does not establish semantic equivalence. Different syntaxes may match the same hostnames, and this first report does not attempt full cross-grammar equivalence.
- The comparator lists are moving URLs. The byte size and SHA-256 above identify only this run's exact snapshots.
- Unsupported lines are counted and examples retained; they are not evaluated.
- The reviewed independent hostname corpus remains empty. Therefore this report gives **no** precision, recall, false-positive rate, application compatibility, real-world ad-blocking efficacy, or performance result.
- A higher unique-rule count can increase both coverage and breakage risk. Each proposed production addition needs provenance, scope and compatibility review.

## Reproduction

The daily workflow runs `tools/comparator_differential.py` after the normal build and stores `comparator-differential.json` plus all fetched snapshots in the `nobledns-build-audit-<run>` artifact. See [workflow run #537](https://github.com/LucentDNS/NobleDNS/actions/runs/43562093365) and [PR #65](https://github.com/LucentDNS/NobleDNS/pull/65).
