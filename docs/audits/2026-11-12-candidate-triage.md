# NobleDNS candidate triage — 2026-11-12

> Research note only. This is not an accepted-rule list and does not change the public subscription.

## Scope and reproducibility

This note examines the candidate-unique domain CSV from the successful upstream audit run on 2026-11-12 07:11:56 UTC. It uses the exact downloaded snapshots recorded in `audit.json`:

| Source | SHA-256 |
|---|---|
| OISD Big | `4d1a6594795bb3c27ab4f4eac58c2eda417ab0e9c803a7d8e07050ce3499d712` |
| anti-AD (AdGuard Home DNS) | `57d5c8fd80e8cf75a55d4e8d2661502b0c353dbf8920fed83fe80a52b1e36e2f` |
| AdRules DNS | `97545e5a82bc976705b4f4fef85683ea8653fa8da9cb195b76a57533d1f46457` |

The candidate-unique CSV contains 183,460 source/domain rows (135,172 OISD, 20,227 anti-AD, 28,061 AdRules). A domain can appear in more than one candidate source. These are domains not present as exact entries in the live baseline; the CSV separately flags domains already covered by a baseline parent-domain rule.

## First-pass mainland-oriented signals

A deliberately simple hostname-token scan was applied to candidate-unique entries ending in `.cn` or `.com.cn`. Counts below are **distinct hostnames across all candidate sources**, not verified advertising/tracking classifications. Tokens are investigation clues only.

| Signal | Distinct .cn/.com.cn hostnames | Interpretation |
|---|---:|---|
| Advertising-related tokens | 53 | Useful review queue; names such as `ad`, `ads`, `alimama`, `mobads` are suggestive but not proof of behavior |
| Analytics/tracking-related tokens | 43 | Requires identifying the actual endpoint function and whether it is first-party/essential |
| HTTPDNS token | 2 | Both are `httpdns-browser.platform.dbankcloud.cn` and `httpdns.platform.dbankcloud.cn` |
| P2P/PCDN token | 6 | All six are Douyu P2P hostnames from AdRules |
| Push/notification token | 5 | Includes WPS, Autohome, Weibo and China Mobile Video-related hostnames; treat as compatibility-sensitive |

These categories overlap. The scan is incomplete by design: mainland services frequently use non-`.cn` hostnames, while legitimate services can contain the same tokens. Do not use these counts as a coverage metric or as an automatic rule-generation input.

### High-priority review queues (not approved blocks)

**Advertising clues:** `ad-market.vivo.com.cn`, `open-ad.vivo.com.cn`, `uapi-ads.vivo.com.cn`, `mobads.baidu.cn`, `mobads-logs.baidu.cn`, `adscdn.baidu.cn`, `ad.sina.com.cn`, `ads.uc.cn`, `ad.docer.wps.cn`.

These are narrowly named advertising-related endpoints and merit endpoint-purpose verification. They must still be checked for shared infrastructure, app dependencies, and whether the candidate rule is already covered by a baseline parent rule.

**Analytics/tracking clues:** `growingio.cn`, `adjust.cn`, `apm.suning.cn`, `analytics.techweb.com.cn`, `analytics.tv189.cn`, `wmedia-track.uc.cn`, `trace.m1905.cn`, `stat.58.xgo.com.cn`.

Do not equate every telemetry or analytics endpoint with unwanted tracking. Some are operational monitoring, crash reporting, anti-fraud, measurement, or service diagnostics. Require evidence of unwanted collection and a compatibility check before accepting any rule.

**HTTPDNS:** `httpdns-browser.platform.dbankcloud.cn`, `httpdns.platform.dbankcloud.cn`.

HTTPDNS is not inherently advertising or malware. It is an alternative application-side name-resolution mechanism used to avoid Local DNS hijacking and improve scheduling/reliability; blocking it can affect application connectivity. Tencent's official product documentation describes these purposes: https://cloud.tencent.com/document/product/379/3519 and https://cloud.tencent.com/document/product/379. Therefore, do not add a blanket HTTPDNS category to the balanced edition. Any endpoint-specific proposal needs evidence that the endpoint is unwanted, not merely that it is HTTPDNS.

**P2P/PCDN:** `p2p-ali.douyucdn.cn`, `p2pchunk-hw.douyucdn.cn`, `p2perrorlog.douyucdn.cn`, `p2plive-ws.douyucdn.cn`, `p2plog.douyucdn.cn`, `p2pvod-ws.douyucdn.cn`.

These are content-delivery/peer-network or associated logging names, not automatically ad/tracker endpoints. Blocking transport endpoints can affect live/video playback; logging endpoints may be separable but still require observed function and narrow scope. The six entries originate from AdRules in this candidate set, so provenance/licensing review is also required before reuse.

**Push/notification:** `push.cmvideo.cn`, `push.wps.cn`, `notify.wps.cn`, `push.app.autohome.com.cn`, `push.mcp.weibo.cn`.

These are explicitly compatibility-sensitive. Do not add them to the blocklist based on name matching.

## Source and licensing gate

- **OISD Big:** the upstream project declares GPL-3.0 for its lists. NobleDNS is GPL-3.0, so this is the clearest candidate for a license-compatible technical evaluation, subject to preserving required notices/attribution and reviewing the actual source content. Its 132,197 domains not covered by a baseline parent rule are far too many to accept wholesale without staged impact review. OISD's own FAQ also documents known functionality trade-offs (including mobile-game reward-video behavior and analytics dashboards) and warns that oversized lists may be truncated or consume excessive client resources. These are reasons to test, not proof that OISD is poor quality.
- **anti-AD:** its README says the generated lists aggregate upstream hosts/ad-filter/adblock lists and user-submitted issues. The repository's code license alone does not establish redistribution rights for every upstream-derived rule. Do not bulk-import its generated output until the relevant provenance and rights are resolved.
- **AdRules:** its README states that generated artifacts follow the original upstream licenses; its Source.md currently lists multiple upstream sources as “No or Unknown”. The merge script's 0BSD license does not make the generated DNS output wholly 0BSD. Do not bulk-import the generated list. Any independently verified hostname still needs documented provenance and rights review before inclusion.

References:
- AdRules README: https://github.com/Cats-Team/AdRules/blob/main/README.md
- AdRules source inventory: https://github.com/Cats-Team/AdRules/blob/script/Source.md
- anti-AD README: https://github.com/privacy-protection-tools/anti-AD/blob/master/README.md
- OISD FAQ: https://oisd.nl/faq

## Decision for NobleDNS

1. No candidate source is accepted wholesale at this stage.
2. Do not add HTTPDNS, P2P/PCDN, push, or generic telemetry categories as blanket blocks.
3. Continue with hostname-level review of the narrow advertising and tracking queues, prioritizing evidence, essential-service dependencies, exact source provenance, and parent-domain scope.
4. OISD is the only candidate currently suitable for a license-compatible technical pilot, but not a wholesale source addition. A staged pilot must remain separate from the public build and include the existing 72 essential-host regression corpus, known-ad sentinels, full build validation, and rollback.
5. Do not expand the parser to accept regexes, wildcards or modifiers merely to ingest candidate syntax. Unsupported syntax remains excluded until semantics and client behavior are explicitly tested.

## Limitations

This note is a lexical triage of domain names, not a DNS traffic study, source-code audit of each endpoint, false-positive measurement, malware verdict, or proof of mainland-specific coverage. No hostname in this note is approved for addition. A future rule proposal must include a concrete behavior claim, evidence URL or upstream line, observation date, exact scope, service-impact review, source/license provenance, and a regression test where appropriate.
