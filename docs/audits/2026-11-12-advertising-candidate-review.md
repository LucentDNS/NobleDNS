# NobleDNS advertising-candidate review — 2026-11-12

> **Research only. No candidate in this report is approved for the public subscription.** This is a hostname/source review, not a live traffic study, app compatibility test, or legal opinion.

## 1. Scope and reproducibility

Reviewed the exact source snapshots from the successful 2026-11-12 upstream audit run. Candidate domains below are exact-unique against the current NobleDNS baseline and are not already covered by a baseline parent-domain block.

| Candidate source | Snapshot SHA-256 |
|---|---|
| OISD Big | `4d1a6594795bb3c27ab4f4eac58c2eda417ab0e9c803a7d8e07050ce3499d712` |
| anti-AD (AdGuard Home DNS) | `57d5c8fd80e8cf75a55d4e8d2661502b0c353dbf8920fed83fe80a52b1e36e2f` |
| AdRules DNS | `97545e5a82bc976705b4f4fef85683ea8653fa8da9cb195b76a57533d1f46457` |

The review queue contains 37 distinct `.cn` / `.com.cn` hostnames with advertising-related lexical signals. The exact original source lines are recorded below so the observations can be reproduced from the snapshots. Every entry is still only a candidate.

## 2. Evidence grading

- **A — corroborated source signal:** appears in at least two of the audited candidate feeds. This is stronger than a single-feed mention, but the feeds may share upstream inputs; it is not independent functional proof.
- **B — single-feed signal:** appears in one audited feed only.
- **C — weak/ambiguous scope:** the hostname name or role suggests a possible ad function but may be a mixed-use endpoint, a publisher/service endpoint, or an obsolete entry. It requires especially careful testing.
- **No functional verdict:** no live DNS/HTTP observation, vendor documentation, app traffic capture, or reproducible controlled test was available in this review. No hostname is labeled “confirmed ad endpoint” solely from its name.

## 3. Candidate inventory

All rules below were simple `||hostname^` patterns in the original snapshots. “Lines” are 1-based line numbers in the exact snapshot named in the source column.

| Hostname | Source snapshot and line | Grade | Review note |
|---|---|---:|---|
| `a.alimama.cn` | OISD 7410 | B | Alibaba advertising-ecosystem name signal; exact endpoint role still unverified |
| `ad-cdn.qtfm.cn` | AdRules 7261 | B | Ad/CDN naming signal; verify whether shared with content delivery |
| `ad-market.vivo.com.cn` | anti-AD 86137 | B | Vendor advertising-market naming signal; device/app impact unknown |
| `ad.3.cn` | AdRules 7344 | B/C | Very generic hostname; weak identity from name alone |
| `ad.95306.cn` | AdRules 7351 | B/C | Very generic hostname; service dependency unknown |
| `ad.adhouyi.cn` | OISD 9891 | B | Ad-named host; operator and actual purpose unverified |
| `ad.api.youshiad.cn` | OISD 9930 | B | Ad-named API; operator and actual purpose unverified |
| `ad.docer.wps.cn` | AdRules 7419 | B/C | WPS/Docer product namespace; high-priority office-app compatibility test |
| `ad.gamebox.360.cn` | OISD 10082 | B/C | Game/product namespace; test game discovery, download and in-app features |
| `ad.jxnews.com.cn` | OISD 10173 | B/C | Publisher namespace; distinguish advertising from publisher content dependencies |
| `ad.molitv.cn` | OISD 10250 | B/C | Video-service namespace; test playback and app startup |
| `ad.quwin.cn` | OISD 10334 | B | Ad-named host; endpoint behavior not independently established |
| `ad.sina.com.cn` | AdRules 7609; OISD 10368 | A/C | Multi-feed signal, but Sina first-party namespace; test login, news, media and embedded content |
| `ad.thepaper.cn` | AdRules 7623 | B/C | Publisher namespace; test article/media loading |
| `ad.thinkmedia.cn` | OISD 10401 | B | Ad-named host; operator and behavior unverified |
| `ads-go.adroi.com.cn` | anti-AD 5591; OISD 12666 | A | Multi-feed ad-named endpoint; verify service identity and whether any shared SDK dependency exists |
| `ads.ccstock.cn` | OISD 12920 | B/C | Financial-information product namespace; test quote/news functions before any decision |
| `ads.ce.cn` | OISD 12926 | B/C | Publisher namespace; test content and media loading |
| `ads.google.cn` | AdRules 9403; OISD 13161 | A/C | Google ad-named host; verify actual DNS usage and avoid overgeneralizing to Google core services |
| `ads.people.com.cn` | AdRules 9608 | B/C | Publisher namespace; test article and media functions |
| `ads.uc.cn` | AdRules 9790; OISD 13543 | A/C | UC namespace; test browser startup, search, download and content rendering |
| `adservice.google.cn` | AdRules 10280 | B/C | Google ad-service naming signal; test only exact host, never infer a broad Google-domain block |
| `advert.mafengwo.cn` | OISD 14441 | B/C | Travel-service namespace; test search, maps, booking and itinerary content |
| `alimama.cn` | anti-AD 7278 | B/C | Parent-domain scope is broad relative to specific ad subdomains; do not accept without proof of whole-zone exclusivity |
| `bm.alimama.cn` | AdRules 24564; OISD 34578 | A | Multi-feed corroboration; still requires endpoint-purpose and app-impact verification |
| `bmvip.alimama.cn` | AdRules 24677; OISD 34670 | A | Multi-feed corroboration; still requires endpoint-purpose and app-impact verification |
| `cb.alimama.cn` | AdRules 29000; OISD 42881 | A | Multi-feed corroboration; still requires endpoint-purpose and app-impact verification |
| `huid.ad.360.cn` | OISD 95046 | B/C | 360 product namespace; verify telemetry/anti-fraud/diagnostic dependencies |
| `img.alimama.cn` | OISD 97674 | B/C | Image hostname under advertising namespace; verify whether assets are shared or required |
| `mobads-logs.baidu.cn` | AdRules 111722; anti-AD 10773 | A/C | Multi-feed signal; logging may be analytics/diagnostic as well as ad measurement; verify app dependencies |
| `mobads.baidu.cn` | AdRules 111726; anti-AD 10774 | A | Multi-feed ad-named signal; verify exact endpoint role and client impact |
| `open-ad.vivo.com.cn` | anti-AD 86142 | B | Vendor advertising naming signal; system/app behavior not tested |
| `palm-ad.cn` | anti-AD 61717; OISD 143719 | A/C | Multi-feed signal but operator and current ownership/usage remain unverified |
| `splash-ads.cdn.unity.cn` | anti-AD 83656 | B/C | Unity game/ad delivery namespace; game startup, reward ads and SDK behavior need testing |
| `splash-ads.unitychina.cn` | anti-AD 83675 | B/C | Unity China game/ad delivery namespace; game startup, reward ads and SDK behavior need testing |
| `tw.alimama.cn` | OISD 200817 | B/C | Alibaba advertising namespace; endpoint role and dependency unknown |
| `uapi-ads.vivo.com.cn` | anti-AD 86144 | B | Vendor advertising API naming signal; device/app impact unknown |

## 4. External corroboration and its limits

The following public community rule collections also contain some matching Baidu, Alimama and UC hostnames:

- A historical public hosts/rule collection lists `mobads.baidu.cn`, `mobads-logs.baidu.cn` and related Baidu endpoints: https://gist.github.com/zhaoxiaobao/d4257b8da57dd36720ac710759aaeace
- A public proxy-rule collection lists `bm.alimama.cn`, `bmvip.alimama.cn` and related Alimama endpoints: https://gist.github.com/lisposter/d44cfbc8329d5fad4f03cf8afd83e66d
- Another public hosts collection groups Alimama hostnames under an Alimama label: https://gist.github.com/SharrHou/e7d1faa819cb5632326625fdb932bec5

These are community-maintained or historical lists, not authoritative vendor documentation, current traffic captures, independent security research, or proof of present-day endpoint behavior. Their publication date, derivation and shared upstream lineage may be uncertain. They are weak corroboration only and must not be used as the sole acceptance basis.


## 4.1 Additional official evidence: Vivo advertising ecosystem

A targeted follow-up search found first-party Vivo documentation relevant to the Vivo-namespaced candidates:

- The official `open-ad.vivo.com.cn` site describes a commercial advertising open platform for advertiser account management, promotion management, campaign data insights, conversion-data upload and audience management: https://open-ad.vivo.com.cn/ . This confirms that the hostname is associated with advertising business operations. It does **not** show that ordinary consumer devices or unrelated apps need this host, nor does it establish that blocking it is safe for all users.
- Vivo's official Marketing API documentation uses `open-ad.vivo.com.cn` for OAuth authorization and advertiser account access: https://open-ad.vivo.com.cn/doc/index?id=388 . This is evidence of an advertiser-facing management/API function, not proof that it is a consumer ad-delivery endpoint.
- Vivo's official advertising-network SDK privacy policy describes advertising SDK use and associated data processing: https://adnet.vivo.com.cn/home/agreement/18 . It establishes the existence and purpose of the Vivo advertising SDK ecosystem, but it does not map `ad-market.vivo.com.cn` or `uapi-ads.vivo.com.cn` to specific request paths or consumer app functions.

**Decision remains unchanged:** `open-ad.vivo.com.cn`, `ad-market.vivo.com.cn` and `uapi-ads.vivo.com.cn` are not approved for the public blocklist. The official evidence improves ecosystem attribution but does not supply the hostname-to-client-traffic mapping, current endpoint observations, or compatibility evidence needed for a block decision.

## 4.2 Official Baidu evidence: confirmed sibling endpoint, not the .cn candidates

Baidu's own MobAds JSSDK deployment page documents the native `Baidu_MobAds_SDK.jar` integration and shows the ad-placement script loading from `mobads.baidu.com/ads/js/hnew.js`. The page says the script is inserted at the location where the advertisement is displayed. This is direct vendor evidence that the `.com` hostname participates in Baidu ad delivery.

Source: https://mobads.baidu.com/ads/indexlp.html

This evidence does **not** prove that `mobads.baidu.cn` is an equivalent current endpoint, and it does not establish the precise purpose of `mobads-logs.baidu.cn`. The latter may be measurement, diagnostics, or a broader SDK logging service. Their inclusion in multiple upstream/community lists remains corroboration, not candidate-specific functional proof. Keep both .cn candidates unapproved; do not infer the parent `baidu.cn` or `baidu.com` zones.

## 5. License and provenance gate

- OISD declares GPL-3.0 for its list. It is the clearest candidate source for a controlled technical evaluation, but any reused rule still needs required attribution/notices and review of third-party inputs.
- anti-AD's repository license does not by itself clear all compiled upstream-derived rules. Do not copy its generated rules into NobleDNS until provenance and redistribution rights are resolved.
- AdRules' generated output follows mixed upstream licensing; its build-script license does not make the generated DNS list wholly 0BSD. Do not copy its generated rules without per-source rights clearance.

A hostname being corroborated across feeds does not cure a licensing or provenance problem. Independent re-verification may establish a reason to block a hostname, but it does not automatically establish redistribution rights for upstream-derived rule text or data.

## 6. Decisions

1. **No additions approved.** This review does not modify `config/sources.json`, `dist/`, `NobleDNS.txt` or the public subscription.
2. Multi-feed candidates are prioritized for deeper endpoint investigation, not auto-accepted.
3. Broad or product-namespace candidates (`alimama.cn`, WPS, 360, Sina, publisher, finance, video and Unity-related endpoints) remain compatibility-sensitive.
4. No parent-domain expansion is proposed. A narrow subdomain signal must never be promoted to a parent-zone block without evidence that the entire zone is dedicated to the unwanted function.
5. HTTPDNS, P2P/PCDN, push and generic telemetry remain separate from advertising review and must not be blanket-blocked.
6. Before any rule is accepted, require: dated evidence of current endpoint behavior; exact hostname and narrow scope; source provenance and redistribution clearance; baseline/exception conflict analysis; suffix-aware essential-service regression; and controlled app/client tests for the affected product category.

## 7. Required next evidence

For the highest-priority clusters, collect controlled DNS observations and test at least:
- Vivo device/app store, system update, app update, login and notification flows for Vivo-namespaced endpoints.
- Baidu app startup, search, map, feed, media and login flows for Baidu-namespaced endpoints.
- UC browser startup, search, download, content rendering and push flows.
- Alibaba/Taobao/1688 login, search, product images, checkout, order status and recommendation flows.
- WPS document open/save, cloud sync, login, templates and update flows.
- Unity games: startup, gameplay, reward-video flow, purchase and update behavior.

A blocked request must be tied to the exact candidate hostname and the affected function. A failed app request alone is not enough: distinguish DNS blocking from routing, TLS, CDN, resolver, server-side and app-version failures. Record the app/client version, OS, date, region/network, resolver, sanitized logs and repeatability.

## 8. Limitations

This review identifies and prioritizes candidate names. It does not prove that any listed hostname currently serves advertising, that blocking it improves privacy, that an app remains functional when blocked, or that the source data may be redistributed. A lack of observed conflict with the current small essential-host corpus is not evidence of universal safety.
