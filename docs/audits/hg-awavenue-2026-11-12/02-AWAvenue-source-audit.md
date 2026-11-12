# AWAvenue source audit — full-protection subscription

> Offline source audit only. No rule from this report is approved for NobleDNS. No production configuration, subscription, or release artifact is modified.

## Snapshot and provenance

- Source: AWAvenue full protection
- URL: https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt
- Downloaded bytes: 23,470
- SHA-256: fdf930d67659f6f1405c81e67c1fb7797145c54296c5ba0398729aa4d846808c
- Raw non-comment rule lines: 976
- Baseline main commit: 4a34cc73e5b90880aa968d23537fec3b615d03a3
- Audit time (UTC): 2026-11-12T09:40:42.002642+00:00
- License assessment: GPL-3.0; repository LICENSE file is present. Preserve attribution and comply with the license and any applicable upstream terms.

## Parser results

| Measure | Count |
|---|---:|
| Unique supported blocking rules | 969 |
| Unique supported blocking domains | 969 |
| Explicit hostname-end rules (||domain^) | 969 |
| Bare hostname-start rules (||domain) | 0 |
| Domains represented by both rule forms | 0 |
| Supported exception domains | 0 |
| Exact rule overlap with NobleDNS baseline | 730 |
| Exact domain overlap with NobleDNS baseline | 730 |
| Exact unique domains vs baseline | 239 |
| Effective new rules after baseline coverage | 49 |
| Effective new domains after baseline coverage | 49 |
| Unique but already covered by a baseline parent rule | 190 |
| Unique domains not covered by a baseline parent rule | 49 |
| Candidate rules that broaden existing baseline scope | 3 |
| New bare-anchor rules with unbounded matching | 0 |
| Baseline block domains newly covered by candidate parent rules | 9 |
| Candidate blocks overlapping baseline exceptions (all source rules) | 1 |
| New candidate blocks overlapping baseline exceptions | 0 |
| Candidate exceptions overlapping baseline blocks | 0 |

### Rejected or unsupported input

| Reason | Lines |
|---|---:|
| wildcard_syntax | 4 |

## Mainland-use lexical signals

These are hostname-string signals only, not verified classifications or evidence of current endpoint behavior.

{
  "cn_suffix": 148,
  "com_cn_suffix": 29,
  "advertising_name_tokens": 161,
  "tracking_or_telemetry_name_tokens": 173,
  "push_name_tokens": 9,
  "httpdns_name_tokens": 2
}

## Regression fixture cross-check

- Essential-service fixture size: 72
- Actual essential-service collisions: **0**
- Known-ad fixture size: 20
- Known-ad hostnames covered: **7**

### Essential-service collisions

[]

### Known-ad fixture coverage

[
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

## Additional review notes

The exact requested main file is the full-protection subscription. The AWAvenue README says this combines advertising, privacy and unwelcome categories; its unwelcome category includes forced updates, P2P/PCDN, push and cloud-control delivery. The repository separately publishes an Ads-only variant described as compatibility/minimal-intervention oriented. That variant is audited separately and contains 658 supported unique blocking domains versus 969 in the full-protection list. The full list has 311 additional domains not present in the Ads-only variant. The source header identifies version 1.7.8-release updated 2026-10-22 21:27:09 UTC+8. Its changelog documents confirmed false-positive removals affecting Youku normal APIs and PDD product-image loading, removal of log.aliyuncs.com and a -normal.zijieapi.com keyword pattern after false-positive reports, and removal of advertiser-backend hosts not requested by client apps. Changelog line references: 701, 741, 743, 745. This history shows active correction, but also confirms that source rules require ongoing endpoint-level scrutiny.

No automatic acceptance is recommended. A source-level match, hostname token, or lack of collision with a small fixture does not establish endpoint purpose, safety, or real-world compatibility.
