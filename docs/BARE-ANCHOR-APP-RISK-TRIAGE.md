# Bare-anchor app compatibility: priority investigations

> Status: unresolved investigation queue. No entry below is a confirmed NobleDNS false positive.
> Production subscription and all 69 bare-anchor rules remain unchanged.

## Why this queue exists

The 69 bare-anchor rules are inherited from the AdGuard DNS Filter. The automated 69-by-72 essential-service sentinel check currently reports no hits, but it cannot cover every app-specific hostname or distinguish telemetry from required application dependencies.

A first public-evidence pass identified three domains worth testing before we make stronger compatibility claims. The exact upstream source line numbers below refer to the run-453 build audit artifact.

| Rule | Source line | Priority | What is known | What remains unknown |
|---|---:|---|---|---|
| `||mssdk.capcutapi.us` | 19072 | High | HaGeZi issue #7901 categorizes it as analytics/metrics/telemetry; an AdGuard issue separately lists it among domains reported in a CapCut signup-page problem | Whether blocking this exact hostname breaks signup, login, editing, export or only optional telemetry in current CapCut versions |
| `||logservice.dbankcloud.cn` | 19205 | High | Public reporting associates it with a Huawei China-region log-server route for a HiViewTunnel component | Which devices/components use it, whether collection is opt-in, whether it is required for diagnostics or other functions, and the impact of blocking |
| `||global-staticplat.cdn.bcebos.com` | 11476 | High | It appears in a public adblocking list; a sandbox report shows a TeraBox process resolving it in a static-widget/resource context | Whether the hostname currently serves ads, functional static assets, or both, and which TeraBox tasks fail if blocked |

Machine-readable references and limitations are recorded in [bare-anchor-app-risk-triage.csv](../benchmark/discovery/bare-anchor-app-risk-triage.csv).

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

## Decision policy

- Do not remove a rule based on one user report.
- Do not retain a rule merely because an upstream list contains it.
- Do not relabel a telemetry endpoint as harmless because an app still launches.
- Require reproducible task-level outcomes, current version identifiers and a matched hostname/rule before deciding.
- If the hostname has mixed use, prefer a narrower rule or no block over knowingly breaking a core user task.
- Keep all three records unresolved until the required tests and independent review are available.

This queue is deliberately small and high priority. It is a starting point for actual compatibility work, not a claim that the other 66 domains have been fully cleared.
