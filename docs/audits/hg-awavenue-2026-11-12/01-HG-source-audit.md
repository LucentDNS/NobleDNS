# HG source audit — hg1.txt and companion hg2.txt

> Offline source audit only. No rule from this report is approved for NobleDNS. No production configuration, subscription, or release artifact is modified.

## Snapshot and provenance

- Source: HG main blocking list (hg1.txt)
- URL: https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt
- Downloaded bytes: 275,409
- SHA-256: feba1cec35500510b8f8590fa49e5c0312c6e5c4e86af2bf6b65eea3ff48e12e
- Raw non-comment rule lines: 13,164
- Baseline main commit: 4a34cc73e5b90880aa968d23537fec3b615d03a3
- Audit time (UTC): 2026-11-12T09:40:41.999356+00:00
- License assessment: No public LICENSE file was found at the repository root during this audit. No retained written permission covering public redistribution is recorded in this audit. Do not redistribute unless explicit permission with scope and conditions is obtained and retained.

## Parser results

| Measure | Count |
|---|---:|
| Unique supported blocking rules | 11,954 |
| Unique supported blocking domains | 11,953 |
| Explicit hostname-end rules (||domain^) | 11,919 |
| Bare hostname-start rules (||domain) | 35 |
| Domains represented by both rule forms | 1 |
| Supported exception domains | 1 |
| Exact rule overlap with NobleDNS baseline | 467 |
| Exact domain overlap with NobleDNS baseline | 468 |
| Exact unique domains vs baseline | 11,485 |
| Effective new rules after baseline coverage | 11,013 |
| Effective new domains after baseline coverage | 11,012 |
| Unique but already covered by a baseline parent rule | 474 |
| Unique domains not covered by a baseline parent rule | 11,011 |
| Candidate rules that broaden existing baseline scope | 86 |
| New bare-anchor rules with unbounded matching | 35 |
| Baseline block domains newly covered by candidate parent rules | 8,728 |
| Candidate blocks overlapping baseline exceptions (all source rules) | 2 |
| New candidate blocks overlapping baseline exceptions | 1 |
| Candidate exceptions overlapping baseline blocks | 0 |

### Rejected or unsupported input

| Reason | Lines |
|---|---:|
| invalid_domain_label | 6 |
| invalid_domain_length_or_trailing_dot | 1 |
| ip_literal_not_domain | 1,004 |
| other_anchor_syntax | 8 |
| other_modifier | 2 |
| regex_or_path_syntax | 6 |
| single_label_not_fqdn | 17 |
| wildcard_syntax | 164 |

## Mainland-use lexical signals

These are hostname-string signals only, not verified classifications or evidence of current endpoint behavior.

{
  "cn_suffix": 1510,
  "com_cn_suffix": 150,
  "advertising_name_tokens": 164,
  "tracking_or_telemetry_name_tokens": 495,
  "push_name_tokens": 38,
  "httpdns_name_tokens": 8
}

## Regression fixture cross-check

- Essential-service fixture size: 72
- Actual essential-service collisions: **2**
- Known-ad fixture size: 20
- Known-ad hostnames covered: **1**

### Essential-service collisions

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

### Known-ad fixture coverage

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
  }
]

## Additional review notes

HG's own README identifies hg1.txt as the blocking list and hg2.txt as its companion allowlist. The companion hg2 file parsed 322 supported exception domains; 65 hierarchical exception/block overlaps with the NobleDNS baseline and 40 overlaps with hg1 were found. It does not provide matching exceptions for the pinduoduo.com or pingan.com parent blocks identified by the essential-service regression fixture. The 35 retained bare-anchor rules need client-specific matching review. 14 bare-anchor entries contain hgzs.uunat.com concatenated directly to the preceding domain fragment; this resembles navigation-host contamination, but the audit does not split or repair them. Examples with source line references: ||5zdw5d.yiqichuanbo.comhgzs.uunat.com (hg1:2463); ||beacon-ad.ztgame.comhgzs.uunat.com (hg1:4371); ||dnda9dg2qc7yvx01.ojfxn.cnhgzs.uunat.com (hg1:5444). The source also contains large numbers of IP-literal, wildcard, single-label and malformed/unsupported entries, all excluded by the NobleDNS parser. The public repository did not expose a LICENSE file at its root.

No automatic acceptance is recommended. A source-level match, hostname token, or lack of collision with a small fixture does not establish endpoint purpose, safety, or real-world compatibility.
