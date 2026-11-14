# Bare-anchor app compatibility: priority investigations

> Status: unresolved investigation queue. No entry below is a confirmed NobleDNS false positive.
> Production subscription and all 69 bare-anchor rules remain unchanged.

## Why this queue exists

The 69 bare-anchor rules are inherited from the AdGuard DNS Filter. The automated 69-by-72 essential-service sentinel check currently reports no hits, but it cannot cover every app-specific hostname or distinguish telemetry from required application dependencies.

A public-evidence pass now has at least one exact-host lead for all 69 bare-anchor rules in the current build. Four remain P0 from the existing payment, sign-up, device-component and static-resource risk set; `mtm.qdqmedia.com` is an additional high-priority conflict because a public badfilter override exists; the other 64 are medium-priority workflow investigations. These are evidence leads, not compatibility clearance.

| Rule | Source line | Priority | Evidence signal | Required workflow |
|---|---:|---|---|---|
| `||mssdk.capcutapi.us` | 19072 | High | HaGeZi classifies telemetry; an AdGuard issue mentions it in a CapCut signup report | CapCut signup/login, editing, upload, export and playback |
| `||logservice.dbankcloud.cn` | 19205 | High | Public reporting associates it with a Huawei China-region HiViewTunnel log-server route | Identify component and opt-in scope; device diagnostics and normal services |
| `||global-staticplat.cdn.bcebos.com` | 11476 | High | Public adblock classification conflicts with a TeraBox static-widget/resource observation | TeraBox login, browse, preview, upload/download and static UI |
| `||logs.juspay.in` | 21748 | High | Official Juspay docs identify a payment-status analytics endpoint | Merchant checkout, payment outcomes, order confirmation and reconciliation |
| `||analysis.polarisoffice.com` | 19279 | Medium | Exact hostname appears in AdGuard mobile tracking/spyware classification | Polaris Office sign-in, cloud sync, open/save and collaboration |
| `||api-ad-callback.mobiuspace.net` | 11625 | Medium | Exact hostname appears in AdGuard MobileFilter adservers section | Identify querying apps; core actions and rewarded-ad flows |
| `||ats.gmarket.co.kr` | 15186 | Medium | Exact hostname appears in AdGuard first-party tracking section | Gmarket account, search, cart, checkout, order and payment |
| `||datadog-log.clovergames.io` | 15234 | Medium | Exact hostname appears in AdGuard first-party tracking section | Clover Games login, gameplay, purchases and account recovery |
| `||taplytics-umami.grubhub.com` | 16203 | Medium | Exact hostname appears in AdGuard first-party tracking section | Grubhub browsing, cart, checkout, order status and account |
| `||api.cloudmobi.net` | 11856 | Medium | Exact hostname appears in AdGuard MobileFilter adservers section | Identify querying apps; core workflows and ad-dependent features |
| `||track.datescan.info` | 18038 | Medium | Exact hostname appears in AdGuard first-party tracking section | Identify embedding site/app; test its core user journey |
| `||events-proxy.mintlify.com` | 184755 | Medium | Exact hostname appears in EasyPrivacy third-party tracking list; request semantics remain unknown | Documentation load, search, navigation and feedback |
| `||deliveryengine.adswizz.com` | 11789 | Medium | Official AdsWizz SDK docs describe ad-server and companion-banner role | Audio playback, ad breaks, resume and player stability |
| `||id-msp.newsbreak.com` | 7988 | Medium | Public privacy scan observes identity/sync iframe request | NewsBreak sign-in, account linking, feed, preferences and consent |
| `||d241ujsiy3yht0.cloudfront.net` | 185395 | Medium | Exact host appears in EasyPrivacy third-party list and storefront script observation | Product browsing, cart, checkout page, support widgets and order status |
| `||c.bigmir.net` | 17021 | Medium | Exact hostname appears in AdGuard mobile and first-party tracking sections | Bigmir content, sign-in, search and media navigation |
| `||config.appjolt.com` | 11876 | Medium | Exact hostname appears in AdGuard MobileFilter adservers section; configuration dependency remains possible | Identify apps; startup, configuration refresh and core features |
| `||d2fj3s7h83rb61.cloudfront.net` | 185400 | Medium | Exact hostname appears in EasyPrivacy third-party list | Identify requester; site assets, page interactions and core journey |
| `||et-code.ru` | 9828 | Medium | Exact hostname appears in AdGuard MobileFilter adservers section | Identify querying apps; launch, sign-in and core app functions |
| `||hitcounter.ru` | 22747 | Medium | Exact hostname appears in AdGuard third-party tracking list | Identify embedding sites; navigation and core actions |
| `||img.opentracker.net` | 17384 | Medium | Exact hostname appears in AdGuard first-party tracking section | Identify requester; image/media loading and core page interactions |
| `||pavoshare.com` | 11475 | Medium | Exact hostname appears in AdGuard MobileFilter adservers section | Identify querying apps; launch and core app workflows |
| `||script.opentracker.net` | 23345 | Medium | Exact hostname appears in AdGuard third-party tracking list | Identify embedding sites; script-dependent page features |
| `||stats.debatdirect.tweedekamer.nl` | 16567 | Medium | Exact hostname appears in AdGuard first-party tracking section | Public parliamentary content, search and navigation |
| `||tms-st.cdn.ngenix.net` | 21916 | Medium | Exact hostname appears in AdGuard third-party tracking list; CDN-style host may be shared | Identify requester; media/static assets and primary workflow |
| `||uts.auction.co.kr` | 16676 | Medium | Exact hostname appears in AdGuard first-party tracking section | Auction account, search, cart, checkout and order status |
| `||zorosrv.com` | 21934 | Medium | Exact hostname appears in AdGuard third-party tracking list | Identify embedding site/app; core user journey |
| `||afdads.com` | 9636 | Medium | AdGuard Ukrainian filter exact-host rule | Identify embedding sites; compare ad/redirect behavior and core navigation. |
| `||allmt.com` | 9649 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requesting sites; test navigation, sign-in and core content. |
| `||almosto.com` | 9652 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test page load, sign-in and core interactions. |
| `||banner-in.net` | 9690 | Medium | AdGuard Ukrainian filter exact-host rule | Identify embedding sites; test content, navigation and any banner-dependent UI. |
| `||banner.kiev.ua` | 9024 | Medium | AdGuard Ukrainian filter and StevenBlack hosts snapshot | Identify current requesters; test Ukrainian-site content, navigation and media. |
| `||clickvip.ru` | 9760 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test click-through, redirect and core page navigation. |
| `||daleelerah.info` | 138196 | Medium | EasyList popup adservers and HostsVN adservers-all | Identify embedding sites; test pop-up behavior, navigation and core content. |
| `||direct-specific.com` | 468 | Medium | AdGuard Base adservers exact-host entry | Identify embedding sites; test page load, navigation and core interactions. |
| `||dl.qcash.ws` | 9804 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test redirects, page content and core navigation. |
| `||eberalofe.pro` | 9814 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test landing pages, redirects and normal site use. |
| `||fjuga.top` | 8565 | Medium | AdGuard ChineseFilter adservers exact-host entry | Identify Chinese apps/sites querying it; test core page and app workflows. |
| `||freecontent.date` | 8438 | Medium | NoCoin list and Bettercap CoinImp injection example | Verify current DNS/HTTP behavior and check whether any legitimate service now shares the domain. |
| `||freecontent.stream` | 8439 | Medium | NoCoin list and Bettercap CoinImp injection example | Verify current DNS/HTTP behavior and check whether any legitimate service now shares the domain. |
| `||gbs.gamingmedia.ru` | 9859 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requesting sites/apps; test game launch, sign-in, gameplay and purchases where relevant. |
| `||globalteaser.ru` | 9877 | Medium | AdGuard Ukrainian filter exact-host rule | Identify embedding sites; test content, navigation and interactive widgets. |
| `||imgg.dt00.net` | 9928 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test image, media, article and page rendering. |
| `||itv.hexun.com` | 179479 | Medium | NobyDa ad rules and Hexun video-ad rule snippet | Test Hexun video launch, playback, ad transitions, resume and related site navigation. |
| `||js.goods.redtram.com` | 9958 | Medium | AdGuard Ukrainian filter exact-host rule | Identify embedding sites; test script-dependent widgets, content and navigation. |
| `||loneday.com` | 10024 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test site navigation, sign-in and core content. |
| `||mjavagames.ru` | 10086 | Medium | AdGuard Ukrainian filter exact-host rule | Identify querying games; test launch, login, gameplay, purchases and reward flows. |
| `||moneymaiker.ru` | 10096 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test account, payment and core site features before any safety conclusion. |
| `||moneysyst.biz` | 10097 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test account, payment and core site features. |
| `||mptri.net` | 10106 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test the embedding site's complete core journey. |
| `||mtm.qdqmedia.com` | 184356 | High | EasyPrivacy international third-party list and OISD; a separate badfilter targets a caret-terminated variant | Identify the site/service, inspect the badfilter rationale and test analytics, consent, form submission and conversion workflows. |
| `||obislame.ru` | 10146 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test content, navigation and account workflows. |
| `||platinumcode.net` | 10194 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test embedding site features and core navigation. |
| `||promoblocks.ru` | 10215 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test promotional widgets and core site functions. |
| `||psma01.com` | 10218 | Medium | AdGuard Ukrainian filter and ntopng tracker list | Identify requester; test analytics-dependent forms, account flows and content. |
| `||psma02.com` | 10219 | Medium | AdGuard Ukrainian filter, ntopng tracker list and NobyDa ad rules | Identify requester; test content, sign-in and app-specific core tasks. |
| `||psma03.com` | 10220 | Medium | AdGuard Ukrainian filter and ntopng tracker list | Identify requester; test content, sign-in and app-specific core tasks. |
| `||rebill.me` | 10254 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test sign-in, billing, checkout and account recovery before concluding it is harmless. |
| `||ruscams.com` | 10293 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; verify the actual request context and whether it is third-party or first-party. |
| `||smart.allocine.fr` | 10335 | Medium | AdGuard Ukrainian filter exact-host rule | Test film pages, trailers, search, account and media playback. |
| `||sn00.net` | 10338 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test page rendering, navigation and core features. |
| `||superpcexpert.ru` | 10356 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test download, support and site navigation. |
| `||talkfusion.com` | 10363 | Medium | AdGuard Ukrainian filter exact-host rule | Identify affected product; test account access, messaging, calls, meetings and recovery. |
| `||timedirect.ru` | 10385 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test scheduling, navigation and core site functions. |
| `||tiz.neosmi.ru` | 10387 | Medium | AdGuard Ukrainian filter exact-host rule | Test Neosmi news loading, article pages, media, search and navigation. |
| `||tmserver-2.net` | 10404 | Medium | AdGuard Ukrainian filter and Tracker Radar domain wiki | Identify requester; test the associated site's full core workflow. |
| `||web-rotation.net` | 10527 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test rotation, redirect, navigation and core content. |
| `||yottos.com` | 10577 | Medium | AdGuard Ukrainian filter, Tracker Radar entity record and StevenBlack hosts snapshot | Identify embedding sites; test recommendation widgets, article loading, navigation and sign-in. |
| `||yxhstwzjbu.info` | 9278 | Medium | AdGuard Ukrainian filter exact-host rule | Identify requester; test page load, redirects and core site behavior. |

Machine-readable evidence, source URLs, limitations and statuses are recorded in [bare-anchor-app-risk-triage.csv](../benchmark/discovery/bare-anchor-app-risk-triage.csv).

## Evidence interpretation

### CapCut SDK hostname

- HaGeZi issue: https://github.com/hagezi/dns-blocklists/issues/7901
- AdGuard issue: https://github.com/AdguardTeam/AdguardFilters/issues/216530

The first is a user-submitted block request with limited details; the second is a user report about a CapCut signup-page issue that mentions this hostname alongside other CapCut endpoints. These are useful leads, not controlled proof that NobleDNS causes a failure. The hostname may be privacy-relevant telemetry and still participate in a workflow dependency.

Required test: current CapCut mobile app and web signup/login, normal editing, upload, export and playback, each with filtering disabled and enabled, while recording the exact DNS query and matched rule.

### Huawei log endpoint

- Hostname association: https://www.netify.ai/resources/hostnames/logservice.dbankcloud.cn
- Component/configuration report: https://bufanche.com/guides/disable-report-components/

The report describes a particular HiViewTunnel component and a China-region log-server route. It must not be generalized into a claim that all Huawei devices require this hostname, or that blocking it is harmless. The component, device/OS version, user-experience opt-in setting and affected task must be established.

Required test: identify the exact component and opt-in setting, then compare device diagnostics, system stability, account/device management and normal network functions with filtering on/off.

### Baidu CDN hostname

- Public adblock classification: https://github.com/r-a-y/mobile-hosts/blob/88c316dea56b1e3f5461f39d66142078fc5716f9/AdguardMobileAds.txt
- Sandbox observation: https://tria.ge/240617-v7lpssxfke/behavioral1

The sandbox trace shows a TeraBox process resolving the hostname in a static-widget/resource context. This does not prove that the content is essential or that blocking causes a user-visible failure, but it is enough to reject a simplistic “ad domain, therefore safe to block” assumption.

Required test: current TeraBox launch, login, file browsing, preview, upload/download and widget/static UI tasks, with DNS logs and matched-rule evidence.

### Juspay payment-status endpoint

- Official vulnerability-disclosure scope: https://juspay.io/vulnerability-disclosure-policy
- Godel integration documentation: https://juspay.gitbooks.io/godel-integration-document/content/7.html

Juspay lists `logs.juspay.in` in its official service scope. Its integration documentation describes POSTing payment status data to this host and explains that these status events support transaction success/failure metrics and merchant-side enhancements. This is stronger evidence of a real payment-workflow role than a generic hostname label, but it does not prove that checkout authorization itself depends on the endpoint.

Required test: on a test merchant or controlled checkout, compare payment success, failure and cancellation; order confirmation; merchant reconciliation and status updates with the hostname allowed and blocked. Do not test by disrupting a live financial transaction.

### Polaris Office hostname

- AdGuard mobile tracking section: https://github.com/AdguardTeam/AdguardFilters/blob/0cbe282a7b179745c082e2d570fc4e9d4b110538/SpywareFilter/sections/mobile.txt
- Mobile spyware list: https://github.com/r-a-y/mobile-hosts/blob/88c316dea56b1e3f5461f39d66142078fc5716f9/AdguardMobileSpyware.txt
- Older AdAway snapshot: https://gist.github.com/JBarnden/cc092e8742796b6ee52bcd204c1d5bbf

The exact hostname appears in AdGuard's mobile tracking section and a separate mobile spyware list. This strengthens the tracking/analytics hypothesis, but does not prove that Polaris Office login, cloud sync, document open/save or collaboration is independent of it.

Required test: sign-in, cloud sync, open/save, collaboration and recovery.

### Mobiuspace ad callback

- AdGuard MobileFilter adservers section: https://github.com/AdguardTeam/AdguardFilters/blob/0cbe282a7b179745c082e2d570fc4e9d4b110538/MobileFilter/sections/adservers.txt
- Mobile ad list: https://github.com/r-a-y/mobile-hosts/blob/88c316dea56b1e3f5461f39d66142078fc5716f9/AdguardMobileAds.txt

The exact hostname appears in AdGuard's current mobile adservers section. This supports an advertising role more directly than domain-name inference, but it does not identify all querying apps or prove that callback failure is harmless to app state or rewarded-ad flows.

Required test: identify current apps that query it, then distinguish optional ad/reward behavior from core app functionality.


### Datescan tracking endpoint

- AdGuard first-party tracking section: https://github.com/AdguardTeam/AdguardFilters/blob/0cbe282a7b179745c082e2d570fc4e9d4b110538/SpywareFilter/sections/tracking_servers_firstparty.txt

The exact hostname is included in AdGuard's first-party tracking section. This supports a tracking classification, but the current evidence does not identify the embedding application or establish whether it shares a first-party operational workflow.

Required test: identify the site/app issuing the query from DNS logs and test its complete core journey with the rule toggled.

### Mintlify events proxy

- URL-query report: https://urlquery.net/report/41b47938-f11c-4a58-a1fa-9f0f471f8852
- Current subdomain observation: https://supax.online/findings?all=1&domain=mintlify.com

A public report of a Claude documentation page records a request to `events-proxy.mintlify.com`, and a current subdomain enumeration confirms the host exists. This establishes observed use, not the payload's purpose. It may be analytics/event collection, but the evidence is insufficient to label it confidently or claim blocking is harmless.

Required test: documentation page load, navigation, search, feedback and any embedded interactive elements with the exact rule toggled.

### AdsWizz delivery endpoint

- Official SDK documentation: https://docs.sdk.adswizz.com/web/index.html
- Official SDK reference: https://docs.sdk.adswizz.com/web/adswizzSDK.html

AdsWizz's own SDK documentation uses a `deliveryengine.adswizz.com` instance as an ad-server endpoint and describes companion-banner delivery. This is strong evidence that the hostname serves advertising, but not proof that blocking it cannot affect audio ad-break state, player callbacks or companion UI.

Required test: audio app cold launch, normal playback, ad-break transitions, playback resume and player stability with the exact rule toggled.

### NewsBreak identity/sync endpoint

- Privacy scan: https://whogetsmydata.com/scan/139909
- Hostname intelligence: https://www.netify.ai/resources/hostnames/id-msp.newsbreak.com

A recent scan observes `id-msp.newsbreak.com` in an `sync-nbu` iframe request, while hostname intelligence associates it with NewsBreak. This supports an identity/sync or tracking role, but it does not show whether sign-in, account linking, feed personalization or consent controls depend on it.

Required test: NewsBreak sign-in, account linking, feed loading, preferences and consent flows.

### CloudFront script endpoint

- EasyPrivacy exact-host entry: https://github.com/easylist/easylist/blob/881ab27bc819bf20b21b174415fcd572ba2ab2bc/easyprivacy/easyprivacy_thirdparty.txt
- Storefront observation: https://seositecheckup.com/seo-audit/www.directfix.com

The exact host appears in EasyPrivacy, and a storefront scan shows a JavaScript asset loaded from it. That is consistent with third-party measurement or marketing code, but a site may also depend on widgets or conversion features delivered by the script.

Required test: storefront product browsing, cart, checkout page, support widgets and order status, without placing a live order.

### Gmarket, Clover Games and Grubhub tracking endpoints

- AdGuard first-party tracking section: https://github.com/AdguardTeam/AdguardFilters/blob/0cbe282a7b179745c082e2d570fc4e9d4b110538/SpywareFilter/sections/tracking_servers_firstparty.txt

This source supports a first-party tracking/analytics classification for the exact hostnames. It does not answer whether any endpoint also participates in application health, fraud prevention, checkout or other operational workflows. Test the listed user journeys before declaring the rules harmless.


### Additional source snapshot notes

The expanded queue also uses the following immutable public snapshots:

- HaGeZi DNS blocklists: `73cfbb14c802c057629c614a679265af081842ac` (2026-11-13); the exact CapCut hostname appears in the dedicated Native TikTok list, not the Multi Normal list.
- AdGuard BrowserExtension: `69965fa59a5d5a44531768780850d3e788fa93e1` (2026-11-09). Its filter metadata identifies filter ID 23 as the **AdGuard Ukrainian filter** (version 2.0.9.55, updated 2026-10-29), not a global tracker list. Many entries are scoped with `$third-party` in browser filtering; that scope cannot be preserved by DNS-only blocking.
- ntopng tracker catalogue: `4b18950f29e95a08be44901a3fc1a331aac5230f` (2026-11-13).
- HostsVN: `cf81902c19468dde6be6a293b17df16165baa427` (2026-11-11).
- NoCoin list: `4b6482588ed108f53366c0855335e50f85efaa5e` (2026-09-12).
- Bettercap example: `eb626871ad99ea8c4f9771f216caa2290e06a058` (2026-07-07).
- NobyDa rules: `0b8d083d444f4476700cb9d5d059c07b42da85eb` (2026-08-12).
- DandelionSprout filter fixes: `3df9d9a4b26268aa7b2f255d3572d088ee8d8503` (2026-11-13).
- OISD domain snapshot: `f6252acb98e26acdf5bfe6dae92516e312b629d6` (2026-11-14).
- DuckDuckGo Tracker Radar Wiki: `11c2634baa0b90969e2ed358bf298f952a8ee922` (2026-11-10).

### Evidence snapshot reproducibility

GitHub-hosted evidence files cited in this report are pinned to immutable source commits inspected on 2026-11-14:

- AdGuard filters: `0cbe282a7b179745c082e2d570fc4e9d4b110538` (2026-11-13)
- EasyList: `881ab27bc819bf20b21b174415fcd572ba2ab2bc` (2026-11-14)
- r-a-y mobile-hosts: `88c316dea56b1e3f5461f39d66142078fc5716f9` (2026-11-13)
- StevenBlack hosts: `35c74714ad86b36806b3f40f3c36abf8b2063cb5` (2026-11-14)

These are evidence snapshots, not NobleDNS production source pins. The production builder continues to use its separately configured and drift-checked upstream source identities.

### Additional exact-host matches from upstream classifications

The AdGuard BrowserExtension source is a regional language filter. Its filter ID 23 is the AdGuard Ukrainian filter, not a universal tracking list. Where a browser rule uses `$third-party`, that context is lost when a hostname is converted to a DNS-level block: DNS filtering cannot tell whether a request originated from a first-party or third-party page. This is why list presence is only a purpose lead and not a safety verdict. See AdGuard's explanation of DNS filtering limitations and request-origin visibility: https://adguard.com/kb/general/dns-filtering/ and https://github.com/AdguardTeam/AdGuardBrowserExtension/blob/69965fa59a5d5a44531768780850d3e788fa93e1/Extension/filters/edge/filters.json.

The following entries were found by matching the exact hostname—not just a parent domain or keyword—against current upstream list files. These classifications are evidence of how the upstream list maintainers categorize the host; they are not independent proof of purpose, and they do not establish that blocking is harmless.

**AdGuard MobileFilter adservers**
- `api.cloudmobi.net`
- `config.appjolt.com`
- `et-code.ru`
- `pavoshare.com`

Source: https://github.com/AdguardTeam/AdguardFilters/blob/0cbe282a7b179745c082e2d570fc4e9d4b110538/MobileFilter/sections/adservers.txt

Required test: identify the applications that actually query each hostname, then test cold launch, sign-in, configuration refresh, core actions and ad/reward-dependent features. In particular, do not assume a hostname beginning with `config.` is optional merely because it is classified in an ad-server list.

**AdGuard tracking classifications**
- `c.bigmir.net` — mobile and first-party tracking sections
- `hitcounter.ru` — third-party tracking section
- `img.opentracker.net` — first-party tracking section
- `script.opentracker.net` — third-party tracking section
- `stats.debatdirect.tweedekamer.nl` — first-party tracking section
- `tms-st.cdn.ngenix.net` — third-party tracking section
- `uts.auction.co.kr` — first-party tracking section
- `zorosrv.com` — third-party tracking section

Sources:
- https://github.com/AdguardTeam/AdguardFilters/blob/0cbe282a7b179745c082e2d570fc4e9d4b110538/SpywareFilter/sections/mobile.txt
- https://github.com/AdguardTeam/AdguardFilters/blob/0cbe282a7b179745c082e2d570fc4e9d4b110538/SpywareFilter/sections/tracking_servers_firstparty.txt
- https://github.com/AdguardTeam/AdguardFilters/blob/0cbe282a7b179745c082e2d570fc4e9d4b110538/SpywareFilter/sections/tracking_servers.txt

Required test: determine which site or app issues each request from DNS logs, then test the relevant content, media, search, account, commerce or public-service workflow. CDN-style and image/script endpoints require particular caution because an endpoint can carry both measurement and user-visible resources.

**EasyPrivacy third-party classifications**
- `d2fj3s7h83rb61.cloudfront.net`

Source: https://github.com/easylist/easylist/blob/881ab27bc819bf20b21b174415fcd572ba2ab2bc/easyprivacy/easyprivacy_thirdparty.txt

Required test: identify the embedding site/app and test script-dependent page behavior, media/assets and the complete core user journey. CloudFront is shared hosting infrastructure; the list match alone does not establish the asset's full role.

The complete hostname-by-hostname evidence URLs, source-line attribution, limitations and required workflow are maintained in [bare-anchor-app-risk-triage.csv](../benchmark/discovery/bare-anchor-app-risk-triage.csv). The CSV is the machine-readable source of detail; the summary above avoids treating list membership as a safety verdict.


## Decision policy

- Do not remove a rule based on one user report.
- Do not retain a rule merely because an upstream list contains it.
- Do not relabel a telemetry endpoint as harmless because an app still launches.
- An upstream tracking label is evidence of purpose, not proof of zero functional dependency.
- Payment, identity, banking, messaging, device-management and system-update workflows receive higher priority than optional ad/reward behavior.
- Require reproducible task-level outcomes, current version identifiers and a matched hostname/rule before deciding.
- If the hostname has mixed use, prefer a narrower rule or no block over knowingly breaking a core user task.
- Keep every entry unresolved until the required tests and independent review are available.

The queue now covers all 69 current bare-anchor rules with public evidence leads. Evidence coverage is not a compatibility clearance; every entry remains unresolved until the relevant task-level tests and independent review are completed. Production blocking rules remain unchanged.


## Browser third-party scope-loss audit

A pinned-source comparison found **30 exact-host rules** in AdGuard BrowserExtension filter ID 23 that carry the `$third-party` modifier. The source is the AdGuard Ukrainian filter at immutable commit `69965fa59a5d5a44531768780850d3e788fa93e1` (not a universal tracker list). Those browser rules apply only when the request is third-party in the browser's request context. DNS filtering cannot see that context, so translating the hostname into a DNS block broadens the effective scope. These matches are purpose evidence only; they are not compatibility clearance and do not prove that the NobleDNS DNS rule is safe or unsafe.

The complete line-numbered inventory is in [browser-third-party-scope-audit.csv](../benchmark/discovery/browser-third-party-scope-audit.csv). CI validates that every row maps to the 69-host queue, the immutable source commit, exact rule syntax, a positive source-line reference and the mandatory DNS scope-loss warning. On every CI run, the workflow downloads the raw file from that immutable commit and verifies that every recorded line number contains the exact rule text. This makes source-line drift or a stale/mistyped reference fail the build.
