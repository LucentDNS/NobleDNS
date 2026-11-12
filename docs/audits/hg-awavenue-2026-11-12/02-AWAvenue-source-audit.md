# AWAvenue source audit — full-protection subscription

> Offline source audit only. No rule from this report is approved for NobleDNS. No production configuration, subscription, or release artifact is modified.

## Snapshot and provenance

- Source: AWAvenue full protection
- URL: https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt
- Downloaded bytes: 23,470
- SHA-256: fdf930d67659f6f1405c81e67c1fb7797145c54296c5ba0398729aa4d846808c
- Raw non-comment rule lines: 976
- Baseline main commit: 7cdf2d36e9333d244e3f236ec964e9b268cf1141
- Audit time (UTC): 2026-11-12T08:24:21.435837+00:00
- License assessment: GPL-3.0; repository LICENSE file is present. Preserve attribution and comply with the license and any applicable upstream terms.

## Parser results

| Measure | Count |
|---|---:|
| Unique supported blocking domains | 969 |
| Explicit hostname-end rules (||domain^) | 969 |
| Bare hostname-start rules (||domain) | 0 |
| Supported exception domains | 0 |
| Exact overlap with NobleDNS baseline | 730 |
| Exact unique domains vs baseline | 239 |
| Unique but already covered by a baseline parent rule | 190 |
| Unique domains not covered by a baseline parent rule | 49 |
| Candidate rules that broaden existing baseline scope | 733 |
| Baseline block domains affected by candidate parent rules | 822 |
| Candidate blocks overlapping baseline exceptions | 1 |
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

## Additional review notes

The exact requested main file is the full-protection subscription. The AWAvenue README says this combines advertising, privacy and unwelcome categories; its unwelcome category includes forced updates, P2P/PCDN, push and cloud-control delivery. The repository separately publishes an Ads-only variant described as compatibility/minimal-intervention oriented. That variant is audited separately and contains 658 supported unique blocking domains versus 969 in the full-protection list. The full list has 311 additional domains not present in the Ads-only variant. This is a source-scope distinction, not a claim that every additional domain is harmful or safe to block.

No automatic acceptance is recommended. A source-level match, hostname token, or lack of collision with a small fixture does not establish endpoint purpose, safety, or real-world compatibility.
