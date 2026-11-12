# AWAvenue Ads-only uncovered-candidate triage

> Research-only hostname triage. This report does not verify endpoint function, authorize blocking, or change the NobleDNS production subscription. Categories below are investigation priorities derived from names and context, not factual classifications.

## Reproducibility

- Audit baseline main commit: `7cdf2d36e9333d244e3f236ec964e9b268cf1141`
- NobleDNS baseline subscription SHA-256: `527d913bb6e385c3dace940a49c462b91b03b5c8845b7c313be36314a88d8fda`
- AWAvenue Ads-only snapshot SHA-256: `f4b660efb332b59960d7c8f2313db2c42af347f41d28c24c0834713bc7809928`
- AWAvenue Full snapshot SHA-256: `fdf930d67659f6f1405c81e67c1fb7797145c54296c5ba0398729aa4d846808c`
- Exact Ads-only source: [AWAvenue Ads-only AdGuard rules](https://github.com/TG-Twilight/AWAvenue-Ads-Rule/blob/main/Filters/AWAvenue-Ads-Rule-Adguard-Only.Ads.txt)
- Exact source line numbers refer to the audited Ads-only snapshot preserved in the audit artifact.

## Why this subset matters

The Ads-only variant contains 658 supported unique domains. Of these, 461 overlap exactly with the NobleDNS baseline, 166 more are already covered by a baseline parent-domain rule, and 31 are not covered by any baseline exact or parent-domain block rule.

The Ads-only candidate set also contains 463 parent-scope broadening rules affecting 527 baseline block domains, and one candidate block conflicts with an existing baseline exception: `m1.ad.10010.com` is covered by candidate rule `||ad.10010.com^`, while NobleDNS has `@@||ad.10010.com^`.

The 31 uncovered hostnames below are the highest-value set for further evidence collection because they represent actual incremental coverage rather than duplicates or already-covered subdomains. None is approved for inclusion.

## Triage list

### A. Advertising / ad-tech naming signal — investigate client traffic and exact function first

| Ads-only source line | Hostname | Current evidence gap |
|---:|---|---|
| 43 | `ad.player.baidu.com` | Name suggests an ad player endpoint; no first-party client request mapping retained |
| 45 | `ad.qq.com` | Could be an advertiser platform or client endpoint; exact role unverified |
| 89 | `ads-jp.tiktok.com` | Regional ads hostname; whether consumer apps request it is unverified |
| 101 | `ads.google.cn` | Ads naming signal; exact client-side request and service scope not established |
| 108 | `ads.pinterest.com` | Ads naming signal; consumer endpoint use not established |
| 130 | `adsebs.ximalaya.com` | Ads naming signal; exact SDK/request evidence missing |
| 131 | `adsense.google.cn` | Advertising product naming; exact DNS endpoint role not established |
| 157 | `adstudio-assets.scdn.co` | Could be advertising creative assets; Spotify app dependency and ad-only scope unverified |
| 189 | `adx.appsdk.com.cn` | Ad-exchange naming; operator and client traffic not established |
| 218 | `api-access.pangolin-sdk-toutiao5.com` | Pangolin SDK naming; exact SDK version and request evidence missing |
| 246 | `bdad.123pan.cn` | Advertising naming; 123pan client function and endpoint purpose unverified |
| 295 | `csjplatform.com` | Ad-platform naming; may be platform/back-office infrastructure rather than client delivery |
| 485 | `proxy.advp.apple.com` | Apple advertising-related naming; exact client traffic and function not established |
| 345 | `heads-ak.spotify.com.edgesuite.net` | Community Spotify-ad lists mention related `heads-ak` hosts, but this exact host still lacks first-party mapping |
| 346 | `heads-fa.spotify.com` | Community Spotify-ad lists mention related `heads-fa` hosts, but this exact host still lacks first-party mapping |

### B. Attribution / analytics / diagnostic naming signal — distinguish unwanted tracking from required SDK services

| Ads-only source line | Hostname | Current evidence gap |
|---:|---|---|
| 74 | `adjust.cn` | Attribution-provider naming; SDK request scope and deep-link/measurement impact unverified |
| 75 | `adjust.com` | Broad provider domain; blanket blocking could affect legitimate attribution or deferred deep links |
| 205 | `analytics.adjust.cn` | Analytics naming; endpoint purpose and app dependency unverified |
| 324 | `g-staic.ganjingworld.com` | Ambiguous static/telemetry-looking label; exact purpose unknown |
| 590 | `tracelog-debug.aiclk.com` | Debug trace naming; whether diagnostic-only or required runtime service is unknown |
| 591 | `tracelog-debug.qquanquan.com` | Debug trace naming; whether diagnostic-only or required runtime service is unknown |

### C. Ambiguous / high compatibility-risk — do not block based on the list name alone

| Ads-only source line | Hostname | Risk requiring resolution |
|---:|---|---|
| 16 | `a0.app.xiaomi.com` | Xiaomi app/service namespace; no reliable ad-only function proof |
| 201 | `alicoccdncnc-xn.inter.71edge.com` | Alibaba-associated CDN hostname; content delivery and service dependency unknown |
| 202 | `alicoccdnct-xn.inter.71edge.com` | Alibaba-associated CDN hostname; content delivery and service dependency unknown |
| 264 | `c.evidon.com` | Consent/privacy-management provider naming; blocking may affect consent controls |
| 473 | `pay.sboot.cn` | Payment-related naming; high false-positive risk until exact owner/function verified |
| 520 | `sdk.cferw.com` | Opaque SDK hostname; owner and purpose unknown |
| 537 | `sdownload.stargame.com` | Download/update/content delivery naming; game update and asset impact unknown |
| 565 | `t.l.qq.com` | Tencent namespace; telemetry, content, or application service function unresolved |
| 616 | `vd6.l.qq.com` | Tencent namespace; video/content service dependency must be tested |
| 644 | `wxsnsdy.wxs.qq.com` | WeChat Moments-related naming; media delivery versus ad-only use unresolved |

## Scope difference: Full versus Ads-only

The audited Full Protection snapshot has 969 supported unique domains; Ads-only has 658. The 311 Full-only domains were compared by hostname-token heuristics. The following counts overlap and are not verified functional classifications:

| Name signal in Full-only set | Distinct hostnames |
|---|---:|
| P2P / PCDN | 22 |
| Push / notification | 9 |
| Update / upgrade | 12 |
| Analytics / tracking / logging / telemetry / monitoring | 131 |
| HTTPDNS | 2 |

The source README explicitly describes Full as Ads + Privacy + Unwelcome, and says Unwelcome includes forced updates, P2P/PCDN, push and cloud-control delivery. This category separation is consistent with the observed Full-only name signals, but the token counts are not proof that every matching hostname performs that function. See the [upstream variant description](https://github.com/TG-Twilight/AWAvenue-Ads-Rule/blob/main/README.md).

The upstream [change log](https://github.com/TG-Twilight/AWAvenue-Ads-Rule/blob/main/assets/README_Update.md) also documents manual removal of confirmed false positives affecting Youku normal APIs and Pinduoduo product-image loading, and removal of advertiser-backend domains that client apps do not request. This is a useful reminder that even a well-maintained ad list requires endpoint-level compatibility evidence.

## Recommended next actions

1. Keep Full Protection out of the balanced NobleDNS edition.
2. Treat Ads-only as a narrower research candidate, not an approved source.
3. Collect first-party SDK/documentation or controlled client traffic evidence for the 15 ad-tech candidates before considering any exact host.
4. Test attribution/deep-link behavior before considering Adjust domains.
5. Do not block the 10 ambiguous/high-risk candidates without clear ownership, purpose and application regression evidence.
6. Resolve the `m1.ad.10010.com` versus `@@||ad.10010.com^` exception conflict before any candidate merge.
7. Keep every candidate outside production until the exact-version AdGuard Android and AdGuard Home compatibility matrix passes.

## Final decision

**No Ads-only candidate is promoted by this report.** The 31 uncovered hostnames are a prioritized evidence backlog, not a recommended blocklist. The Full-only delta is materially broader in telemetry, P2P/PCDN, push and update-related name signals, so Ads-only remains the only AWAvenue variant worth further compatibility-first investigation.
