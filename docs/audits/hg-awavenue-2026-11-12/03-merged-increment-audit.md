# HG + AWAvenue merged incremental audit

> Research only. No rule is added to NobleDNS. This report compares the two exact requested sources with the current published main-branch subscription.

## Reproducibility

- Baseline commit: 7cdf2d36e9333d244e3f236ec964e9b268cf1141
- Baseline URL: https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt
- Baseline SHA-256: 527d913bb6e385c3dace940a49c462b91b03b5c8845b7c313be36314a88d8fda
- Baseline blocking rules: 303,625
- Baseline active exceptions: 11
- Rule cap: 500,000
- HG snapshot SHA-256: feba1cec35500510b8f8590fa49e5c0312c6e5c4e86af2bf6b65eea3ff48e12e
- AWAvenue full snapshot SHA-256: fdf930d67659f6f1405c81e67c1fb7797145c54296c5ba0398729aa4d846808c
- Audit time UTC: 2026-11-12T08:24:21.395923+00:00

## Cross-source overlap

| Measure | Count |
|---|---:|
| HG unique supported blocking domains | 11,953 |
| AWAvenue full unique supported blocking domains | 969 |
| Exact domain overlap | 241 |
| HG + AWAvenue full union | 12,681 |
| HG + AWAvenue exact-rule overlap | 241 |
| HG + AWAvenue Ads-only overlap | 185 |
| HG + AWAvenue Ads-only union | 12,426 |

## Increment relative to NobleDNS

| Measure | Count |
|---|---:|
| Exact new rules vs baseline | 11,649 |
| New unique domains vs baseline | 11,647 |
| New domains not already covered by a baseline parent rule | 11,055 |
| Candidate rules that broaden existing baseline scope | 1,088 |
| Baseline block domains affected by candidate parent rules | 9,984 |
| Candidate blocks overlapping baseline exceptions | 2 |
| Candidate exceptions overlapping baseline blocks | 0 |
| Projected total if every exact new block rule were appended | 315,285 / 500,000 |

The projected count is arithmetic only. It does not establish that the candidate rules are appropriate, safe, or accepted.

## Regression fixture results

### Essential services

[
  {
    "hostname": "bank.pingan.com",
    "matching_rules": [
      "||pingan.com^"
    ]
  },
  {
    "hostname": "pinduoduo.com",
    "matching_rules": [
      "||pinduoduo.com^"
    ]
  }
]

### Known advertising infrastructure

[
  {
    "hostname": "doubleclick.net",
    "matching_rules": [
      "||doubleclick.net^"
    ]
  },
  {
    "hostname": "googleadservices.com",
    "matching_rules": [
      "||googleadservices.com^"
    ]
  },
  {
    "hostname": "adservice.google.com",
    "matching_rules": [
      "||adservice.google.com^"
    ]
  },
  {
    "hostname": "moatads.com",
    "matching_rules": [
      "||moatads.com^"
    ]
  },
  {
    "hostname": "adcolony.com",
    "matching_rules": [
      "||adcolony.com^"
    ]
  },
  {
    "hostname": "vungle.com",
    "matching_rules": [
      "||vungle.com^"
    ]
  },
  {
    "hostname": "applovin.com",
    "matching_rules": [
      "||applovin.com^"
    ]
  },
  {
    "hostname": "unityads.unity3d.com",
    "matching_rules": [
      "||unityads.unity3d.com^"
    ]
  }
]

## HG companion allowlist impact

- Supported HG2 exception domains: 322
- HG2 exception/block hierarchy overlaps with NobleDNS baseline: 65
- HG2 exception/block hierarchy overlaps with HG1: 40
- HG2 does not provide a matching exception for the HG parent blocks pinduoduo.com and pingan.com.

Using HG2 as an allowlist is not a neutral operation: exceptions can neutralize matching baseline blocking rules. Do not merge it into the NobleDNS main subscription without a separate, reviewed exception policy.

## Source-specific decision

### HG

Do not bulk-import. The source contains two parent-domain rules that collide with the existing essential-service fixture: pinduoduo.com and pingan.com. HG2 does not repair those conflicts. The parser also excludes 1,004 IP-literal/IPv4-like entries, 164 wildcard entries, 17 single-label entries, and other malformed/unsupported syntax. Thirty-five valid bare-anchor rules remain semantically broader than caret-bounded rules and require client-specific testing. No public LICENSE file was found at the repository root; retain explicit written permission covering public redistribution and licensing before any inclusion.

### AWAvenue full protection

Do not bulk-import into the single balanced edition yet. The full subscription combines advertising, privacy and unwelcome categories. Its own README says the unwelcome category includes forced updates, P2P/PCDN, push and cloud-control delivery, which can affect normal service behavior. The small 72-host essential fixture had no collision in this snapshot, but that is not a real-world compatibility guarantee. Four wildcard rules remain unsupported and three raw rules are duplicates. The repository provides GPL-3.0 licensing information.

### AWAvenue Ads-only comparison

The separately published Ads-only variant contains 658 supported unique domains, 311 fewer than the full list. It is more consistent with a conservative ad-only evaluation than silently using the full-protection list, but still requires its own overlap, endpoint evidence and client compatibility review. It is not substituted for the requested full-list audit.

## Final audit conclusion

**No source is approved for automatic inclusion.** HG is blocked by confirmed essential-fixture conflicts and unresolved public redistribution terms. AWAvenue full protection is too broad for direct bulk inclusion in the balanced edition without separating its privacy/unwelcome effects and completing client tests. If further evaluation is pursued, the AWAvenue Ads-only variant is the narrower pilot candidate; HG requires individual rule review, not wholesale merging.

No production source configuration, public rules, manifest, subscription, or release was modified.
