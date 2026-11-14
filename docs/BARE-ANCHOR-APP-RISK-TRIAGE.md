# Bare-anchor app compatibility: priority investigations

> Status: unresolved investigation queue. No entry below is a confirmed NobleDNS false positive.
> Production subscription and all 69 bare-anchor rules remain unchanged.

## Why this queue exists

The 69 bare-anchor rules are inherited from the AdGuard DNS Filter. The automated 69-by-72 essential-service sentinel check currently reports no hits, but it cannot cover every app-specific hostname or distinguish telemetry from required application dependencies.

A public-evidence pass has identified 27 unique hostnames requiring targeted investigation. Four are P0 because of potential payment, sign-up, device-component or static-resource impact; 23 are medium-priority workflow checks. Duplicate records from the prior expansion were reconciled rather than counted twice. These are investigation priorities, not findings that the rules are incorrect.

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

- EasyPrivacy exact-host entry: https://github.com/easylist/easylist/blob/6db59e375bb5c16601f036f804111eaee296fa73/easyprivacy/easyprivacy_thirdparty.txt
- Storefront observation: https://seositecheckup.com/seo-audit/www.directfix.com

The exact host appears in EasyPrivacy, and a storefront scan shows a JavaScript asset loaded from it. That is consistent with third-party measurement or marketing code, but a site may also depend on widgets or conversion features delivered by the script.

Required test: storefront product browsing, cart, checkout page, support widgets and order status, without placing a live order.

### Gmarket, Clover Games and Grubhub tracking endpoints

- AdGuard first-party tracking section: https://github.com/AdguardTeam/AdguardFilters/blob/0cbe282a7b179745c082e2d570fc4e9d4b110538/SpywareFilter/sections/tracking_servers_firstparty.txt

This source supports a first-party tracking/analytics classification for the exact hostnames. It does not answer whether any endpoint also participates in application health, fraud prevention, checkout or other operational workflows. Test the listed user journeys before declaring the rules harmless.


### Evidence snapshot reproducibility

GitHub-hosted evidence files cited in this report are pinned to immutable source commits inspected on 2026-11-14:

- AdGuard filters: `0cbe282a7b179745c082e2d570fc4e9d4b110538` (2026-11-13)
- EasyList: `6db59e375bb5c16601f036f804111eaee296fa73` (2026-11-14)
- r-a-y mobile-hosts: `88c316dea56b1e3f5461f39d66142078fc5716f9` (2026-11-13)
- StevenBlack hosts: `35c74714ad86b36806b3f40f3c36abf8b2063cb5` (2026-11-14)

These are evidence snapshots, not NobleDNS production source pins. The production builder continues to use its separately configured and drift-checked upstream source identities.

### Additional exact-host matches from upstream classifications

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

Source: https://github.com/easylist/easylist/blob/6db59e375bb5c16601f036f804111eaee296fa73/easyprivacy/easyprivacy_thirdparty.txt

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

The 27 entries are a prioritized slice of the 69-rule inventory, not a claim that the other 42 domains have been cleared. Production blocking rules remain unchanged.
