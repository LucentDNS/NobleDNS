# Bare-anchor app compatibility: priority investigations

> Status: unresolved investigation queue. No entry below is a confirmed NobleDNS false positive.
> Production subscription and all 69 bare-anchor rules remain unchanged.

## Why this queue exists

The 69 bare-anchor rules are inherited from the AdGuard DNS Filter. The automated 69-by-72 essential-service sentinel check currently reports no hits, but it cannot cover every app-specific hostname or distinguish telemetry from required application dependencies.

A public-evidence pass has identified 12 hostnames requiring targeted investigation. Four are P0 because of potential payment, sign-up, device-component or static-resource impact; eight are medium-priority workflow checks. These are investigation priorities, not findings that the rules are incorrect.

| Rule | Source line | Priority | Evidence signal | Required workflow |
|---|---:|---|---|---|
| `||mssdk.capcutapi.us` | 19072 | High | HaGeZi classifies it as analytics/telemetry; an AdGuard issue separately mentions it in a CapCut signup problem report | CapCut signup/login, editing, upload, export and playback |
| `||logservice.dbankcloud.cn` | 19205 | High | Public reporting associates it with a Huawei China-region HiViewTunnel log-server route | Identify component and opt-in scope; device/system diagnostics and normal device services |
| `||global-staticplat.cdn.bcebos.com` | 11476 | High | Public adblock classification conflicts with a TeraBox process observation in a static-widget/resource context | TeraBox login, file browse, preview, upload/download and static UI |
| `||logs.juspay.in` | 21748 | High | Official Juspay documentation identifies it as a payment-status analytics endpoint | Merchant checkout, payment success/failure/cancel, order confirmation and status reconciliation |
| `||analysis.polarisoffice.com` | 19279 | Medium | Appears in public hosts lists grouped under Polaris Office | Polaris Office sign-in, cloud sync, open/save and collaboration |
| `||api-ad-callback.mobiuspace.net` | 11625 | Medium | Exact hostname appears in multiple public mobile-ad lists | Identify affected apps; launch, sign-in, core actions and rewarded-ad-dependent features |
| `||ats.gmarket.co.kr` | 15186 | Medium | Listed in AdGuard's first-party tracking section | Gmarket account, search, cart, checkout, order and payment |
| `||datadog-log.clovergames.io` | 15234 | Medium | Listed in AdGuard's first-party tracking section | Clover Games login, gameplay, purchases and account recovery |
| `||taplytics-umami.grubhub.com` | 16203 | Medium | Listed in AdGuard's first-party tracking section | Grubhub browsing, cart, checkout, order status and account |

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

- Public adblock classification: https://github.com/r-a-y/mobile-hosts/blob/master/AdguardMobileAds.txt
- Sandbox observation: https://tria.ge/240617-v7lpssxfke/behavioral1

The sandbox trace shows a TeraBox process resolving the hostname in a static-widget/resource context. This does not prove that the content is essential or that blocking causes a user-visible failure, but it is enough to reject a simplistic “ad domain, therefore safe to block” assumption.

Required test: current TeraBox launch, login, file browsing, preview, upload/download and widget/static UI tasks, with DNS logs and matched-rule evidence.

### Juspay payment-status endpoint

- Official vulnerability-disclosure scope: https://juspay.io/vulnerability-disclosure-policy
- Godel integration documentation: https://juspay.gitbooks.io/godel-integration-document/content/7.html

Juspay lists `logs.juspay.in` in its official service scope. Its integration documentation describes POSTing payment status data to this host and explains that these status events support transaction success/failure metrics and merchant-side enhancements. This is stronger evidence of a real payment-workflow role than a generic hostname label, but it does not prove that checkout authorization itself depends on the endpoint.

Required test: on a test merchant or controlled checkout, compare payment success, failure and cancellation; order confirmation; merchant reconciliation and status updates with the hostname allowed and blocked. Do not test by disrupting a live financial transaction.

### Polaris Office hostname

- AdAway hosts snapshot: https://git.eeqj.de/sneak/sneak.berlin-dns-blocklist/src/branch/main/hostlists/adaway-default-hosts.txt
- Public hosts-list mirror: https://gist.github.com/JBarnden/cc092e8742796b6ee52bcd204c1d5bbf

Multiple list appearances are weak corroboration only. They do not establish the endpoint's current purpose, and they do not prove that blocking is harmless to Polaris Office features.

Required test: sign-in, cloud sync, open/save, collaboration and recovery.

### Mobiuspace ad callback

- Public AdAway list mirror: https://git.eeqj.de/sneak/sneak.berlin-dns-blocklist/src/branch/main/hostlists/adaway-default-hosts.txt
- Mobile ad list: https://github.com/r-a-y/mobile-hosts/blob/master/AdguardMobileAds.txt

The exact hostname appears in multiple public mobile-ad lists. These lists may share upstream ancestry and are not independent ground truth. Treat the advertising callback hypothesis as plausible, not proven.

Required test: identify current apps that query it, then distinguish optional ad/reward behavior from core app functionality.

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

- EasyPrivacy exact-host entry: https://github.com/easylist/easylist/blob/master/easyprivacy/easyprivacy_thirdparty.txt
- Storefront observation: https://seositecheckup.com/seo-audit/www.directfix.com

The exact host appears in EasyPrivacy, and a storefront scan shows a JavaScript asset loaded from it. That is consistent with third-party measurement or marketing code, but a site may also depend on widgets or conversion features delivered by the script.

Required test: storefront product browsing, cart, checkout page, support widgets and order status, without placing a live order.

### Gmarket, Clover Games and Grubhub tracking endpoints

- AdGuard first-party tracking section: https://github.com/AdguardTeam/AdguardFilters/blob/master/SpywareFilter/sections/tracking_servers_firstparty.txt

This source supports a first-party tracking/analytics classification for the exact hostnames. It does not answer whether any endpoint also participates in application health, fraud prevention, checkout or other operational workflows. Test the listed user journeys before declaring the rules harmless.

## Decision policy

- Do not remove a rule based on one user report.
- Do not retain a rule merely because an upstream list contains it.
- Do not relabel a telemetry endpoint as harmless because an app still launches.
- An upstream tracking label is evidence of purpose, not proof of zero functional dependency.
- Payment, identity, banking, messaging, device-management and system-update workflows receive higher priority than optional ad/reward behavior.
- Require reproducible task-level outcomes, current version identifiers and a matched hostname/rule before deciding.
- If the hostname has mixed use, prefer a narrower rule or no block over knowingly breaking a core user task.
- Keep every entry unresolved until the required tests and independent review are available.

The 12 entries are a prioritized slice of the 69-rule inventory, not a claim that the other 57 domains have been cleared. Production blocking rules remain unchanged.
