# RC2.2 baseline verification

The RC3 candidate builder was run offline against the two exact source snapshots supplied for the RC2.2 work.

| Metric | Result |
|---|---:|
| AdGuard simple blocks | 187,612 |
| HaGeZi simple blocks | 207,300 |
| Common | 92,937 |
| AdGuard-only | 94,675 |
| HaGeZi-only | 114,363 |
| Merged unique block rules | 301,975 |
| Separate source exceptions | 11 |
| AdGuard excluded lines | 882 |
| HaGeZi excluded lines | 1 |

A direct set comparison between the supplied RC2.2 builder and the RC3 candidate builder on the same snapshots produced **0 added rules and 0 removed rules** (301,975 rules on both sides). This establishes rule-set equivalence for these snapshots; it does not establish live client compatibility or a real-world false-positive rate.

The generated main subscription SHA256 is recorded in `dist/manifest.json`. The rule file uses a stable header so its SHA256 changes only when the actual subscription content changes.
