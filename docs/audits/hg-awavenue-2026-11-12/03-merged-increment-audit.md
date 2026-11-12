# HG + AWAvenue merged incremental audit

> Research only. No rule is added to NobleDNS. This report compares the two exact requested sources with the current published main-branch subscription.

## Reproducibility

- Baseline commit: 4a34cc73e5b90880aa968d23537fec3b615d03a3
- Baseline URL: https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt
- Baseline SHA-256: c333003bb59f393bf0364e97a4b3704ded2c489c878af9e5f434dc39da71b397
- Baseline manifest SHA-256: 7a7290736b71fd36846dc0a7393c33510ff68799a3a5744d2f335c91b65de274
- Baseline manifest integrity: PASS (manifest version 1.0.3, status PUBLIC, built 2026-11-12T08:33:02.389220+00:00)
- Baseline blocking rules: 303,686
- Baseline active exceptions: 11
- Rule cap: 500,000
- HG snapshot SHA-256: feba1cec35500510b8f8590fa49e5c0312c6e5c4e86af2bf6b65eea3ff48e12e
- AWAvenue full snapshot SHA-256: fdf930d67659f6f1405c81e67c1fb7797145c54296c5ba0398729aa4d846808c
- Audit time UTC: 2026-11-12T09:05:37.950074+00:00

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
| Effective new rules after baseline coverage | 11,058 |
| Effective new domains after baseline coverage | 11,057 |
| New domains not already covered by a baseline parent rule | 11,056 |
| Candidate rules that broaden existing baseline scope | 89 |
| New bare-anchor rules with unbounded matching | 35 |
| Baseline block domains newly covered by candidate parent rules | 8,737 |
| Candidate blocks overlapping baseline exceptions (all source rules) | 2 |
| New candidate blocks overlapping baseline exceptions | 1 |
| Candidate exceptions overlapping baseline blocks | 0 |
| Projected total if every exact new block rule were appended | 315,346 / 500,000 |

The projected count is arithmetic only. It does not establish that the candidate rules are appropriate, safe, or accepted.

## Regression fixture results

### Essential services

[
  {
    "hostname": "bank.pingan.com",
    "matching_rules": [
      "||pingan.com^"
    ],
    "source_lines": {
      "||pingan.com^": [
        "hg1:9499"
      ]
    }
  },
  {
    "hostname": "pinduoduo.com",
    "matching_rules": [
      "||pinduoduo.com^"
    ],
    "source_lines": {
      "||pinduoduo.com^": [
        "hg1:9497"
      ]
    }
  }
]

### Known advertising infrastructure

[
  {
    "hostname": "doubleclick.net",
    "matching_rules": [
      "||doubleclick.net^"
    ],
    "source_lines": {
      "||doubleclick.net^": [
        "hg1:5476"
      ]
    }
  },
  {
    "hostname": "googleadservices.com",
    "matching_rules": [
      "||googleadservices.com^"
    ],
    "source_lines": {
      "||googleadservices.com^": [
        "awavenue_full:426"
      ]
    }
  },
  {
    "hostname": "adservice.google.com",
    "matching_rules": [
      "||adservice.google.com^"
    ],
    "source_lines": {
      "||adservice.google.com^": [
        "awavenue_full:141"
      ]
    }
  },
  {
    "hostname": "moatads.com",
    "matching_rules": [
      "||moatads.com^"
    ],
    "source_lines": {
      "||moatads.com^": [
        "awavenue_full:599"
      ]
    }
  },
  {
    "hostname": "adcolony.com",
    "matching_rules": [
      "||adcolony.com^"
    ],
    "source_lines": {
      "||adcolony.com^": [
        "awavenue_full:73"
      ]
    }
  },
  {
    "hostname": "vungle.com",
    "matching_rules": [
      "||vungle.com^"
    ],
    "source_lines": {
      "||vungle.com^": [
        "awavenue_full:923"
      ]
    }
  },
  {
    "hostname": "applovin.com",
    "matching_rules": [
      "||applovin.com^"
    ],
    "source_lines": {
      "||applovin.com^": [
        "awavenue_full:275"
      ]
    }
  },
  {
    "hostname": "unityads.unity3d.com",
    "matching_rules": [
      "||unityads.unity3d.com^"
    ],
    "source_lines": {
      "||unityads.unity3d.com^": [
        "awavenue_full:892",
        "awavenue_full:980"
      ]
    }
  }
]

## HG companion allowlist impact

- Supported HG2 exception domains: 322
- HG2 exception/block hierarchy overlaps with NobleDNS baseline: 65
- HG2 exception/block hierarchy overlaps with HG1: 40
- HG2 does not provide a matching exception for the HG parent blocks pinduoduo.com and pingan.com.

Using HG2 as an allowlist is not a neutral operation: exceptions can neutralize matching baseline blocking rules. Do not merge it into the NobleDNS main subscription without a separate, reviewed exception policy.

## License review

- NobleDNS project: GPL-3.0 (LICENSE SHA-256 3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986)
- AWAvenue: GPL-3.0 (LICENSE SHA-256 589ed823e9a84c56feb95ac58e7cf384626b9cbf4fda2a907bc36e103de1bad2)
- HG: no public LICENSE file was found in the repository root, and this audit has no retained written permission covering public redistribution. Do not copy rules into the public project unless explicit maintainer permission with scope and conditions is obtained and retained.
- NobleDNS and AWAvenue both use GPL-3.0, so their license family is aligned at a high level. Preserve upstream attribution and all applicable GPL notices/terms.

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
