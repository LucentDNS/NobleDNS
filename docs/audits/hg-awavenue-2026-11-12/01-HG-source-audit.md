# HG source audit — hg1.txt and companion hg2.txt

> Offline source audit only. No rule from this report is approved for NobleDNS. No production configuration, subscription, or release artifact is modified.

## Snapshot and provenance

- Source: HG main blocking list (hg1.txt)
- URL: https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt
- Downloaded bytes: 275,409
- SHA-256: feba1cec35500510b8f8590fa49e5c0312c6e5c4e86af2bf6b65eea3ff48e12e
- Raw non-comment rule lines: 13,164
- Baseline main commit: 7cdf2d36e9333d244e3f236ec964e9b268cf1141
- Audit time (UTC): 2026-11-12T08:24:21.432751+00:00
- License assessment: No public LICENSE file was found at the repository root during this audit. No retained written permission covering public redistribution is recorded in this audit. Do not redistribute unless explicit permission with scope and conditions is obtained and retained.

## Parser results

| Measure | Count |
|---|---:|
| Unique supported blocking domains | 11,953 |
| Explicit hostname-end rules (||domain^) | 11,919 |
| Bare hostname-start rules (||domain) | 35 |
| Supported exception domains | 1 |
| Exact overlap with NobleDNS baseline | 468 |
| Exact unique domains vs baseline | 11,485 |
| Unique but already covered by a baseline parent rule | 475 |
| Unique domains not covered by a baseline parent rule | 11,010 |
| Candidate rules that broaden existing baseline scope | 519 |
| Baseline block domains affected by candidate parent rules | 9,326 |
| Candidate blocks overlapping baseline exceptions | 2 |
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
    ]
  },
  {
    "hostname": "pinduoduo.com",
    "matching_rules": [
      "||pinduoduo.com^"
    ]
  }
]

### Known-ad fixture coverage

[
  {
    "hostname": "doubleclick.net",
    "matching_rules": [
      "||doubleclick.net^"
    ]
  }
]

## Additional review notes

HG's own README identifies hg1.txt as the blocking list and hg2.txt as its companion allowlist. The companion hg2 file parsed 322 supported exception domains; 65 hierarchical exception/block overlaps with the NobleDNS baseline and 40 overlaps with hg1 were found. It does not provide matching exceptions for the pinduoduo.com or pingan.com parent blocks identified by the essential-service regression fixture. The 35 retained bare-anchor rules need client-specific matching review. The source also contains large numbers of IP-literal, wildcard, single-label and malformed/unsupported entries, all excluded by the NobleDNS parser. The public repository did not expose a LICENSE file at its root.

No automatic acceptance is recommended. A source-level match, hostname token, or lack of collision with a small fixture does not establish endpoint purpose, safety, or real-world compatibility.
