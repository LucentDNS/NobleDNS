# Third-Party Notices

NobleDNS incorporates and processes third-party DNS filtering rules.
NobleDNS does not claim original authorship of upstream rule content.

## 1. AdGuard DNS Filter

- Project: AdGuard DNS Filter
- Maintainer: AdGuard
- Official repository:
  https://github.com/AdguardTeam/AdGuardSDNSFilter
- Upstream rule:
  https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
- License: GPL-3.0
- License file:
  https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE

## 2. HaGeZi Multi PRO Mini

- Project: HaGeZi DNS Blocklists
- Maintainer: HaGeZi
- Official repository:
  https://github.com/hagezi/dns-blocklists
- Upstream rule:
  https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.mini.txt
- License: GPL-3.0
- License file:
  https://github.com/hagezi/dns-blocklists/blob/main/LICENSE

NobleDNS uses Multi PRO as its only HaGeZi Multi tier. HaGeZi documents the Multi tiers as cumulative, so Multi Normal is not subscribed alongside PRO. HaGeZi also identifies third-party input data that may be subject to separate terms. Those terms must be respected where applicable.

## 3. HaGeZi TIF Mini

- Project: HaGeZi DNS Blocklists — Threat Intelligence Feeds
- Maintainer: HaGeZi
- Official repository:
  https://github.com/hagezi/dns-blocklists
- Upstream rule:
  https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt
- License: GPL-3.0
- License file:
  https://github.com/hagezi/dns-blocklists/blob/main/LICENSE

TIF Mini is a threat-intelligence add-on for malware, phishing and related malicious infrastructure. HaGeZi documents it as a size-optimized version of TIF Medium. It complements one selected Multi main tier; it is not a replacement for or a parallel Multi tier. NobleDNS selects Mini rather than the full or Medium TIF feed to respect the project's rule ceiling. HaGeZi's disclaimer and any third-party input terms remain applicable.

## 4. AWAvenue Ads Rule (Only Ads)

- Project: AWAvenue 秋风广告规则
- Maintainer: TG-Twilight
- Official repository:
  https://github.com/TG-Twilight/AWAvenue-Ads-Rule
- Upstream rule: dedicated AdGuard `Only.Ads` variant (advertising category only)
  https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Adguard-Only.Ads.txt
- License: GPL-3.0
- License file:
  https://github.com/TG-Twilight/AWAvenue-Ads-Rule/blob/main/LICENSE

NobleDNS uses the dedicated Ads-only variant, not the upstream Full Protection, No Privacy or No Unwelcome variants. The builder preserves supported AdGuard DNS hostname rules, including documented wildcard patterns with a static suffix and the `$important` modifier. Unsupported or ambiguous lines are recorded as parser exclusions rather than rewritten.

## 5. NobleDNS modifications

NobleDNS retrieves, validates, filters, deduplicates and compiles
the approved upstream sources.

The project preserves supported rule syntax and excludes unsupported
syntax rather than silently converting it into guessed equivalents.

The resulting files contain upstream-derived material and must not
be represented as wholly original NobleDNS content.

## 6. Licensing and redistribution

The original NobleDNS project code is licensed under
GNU GPL version 3, GPL-3.0-only.

Upstream rule content remains subject to its applicable copyright,
license terms and third-party rights.

Redistributors must retain applicable copyright and license notices,
provide the relevant license text, and comply with all applicable
redistribution requirements.

This notice is an attribution and licensing guide. It does not
replace the upstream license texts or grant rights beyond those
licenses.

## 7. Content designation and disclaimer

Any domain appearing in a compiled NobleDNS subscription is included as a DNS blocking target only. Its presence does not mean NobleDNS hosts, publishes, operates, endorses or distributes the associated website or its content.

AdGuard, HaGeZi and AWAvenue are independent upstream projects.
NobleDNS is not affiliated with or endorsed by any upstream project.

## 8. HaGeZi upstream disclaimer

HaGeZi publishes its DNS blocklists under GPL-3.0 and states that the GPL license copy must accompany redistribution. The GPL-3.0 text is included in this repository and in the generated build artifact.

HaGeZi also publishes a separate disclaimer in its [official repository README](https://github.com/hagezi/dns-blocklists#disclaimer). The disclaimer addresses, among other things, the lists being provided without warranty, the absence of guarantees against false positives or missed domains, the technical (not accusatory or endorsing) nature of domain inclusion, user responsibility for deployment, and the fact that some upstream inputs may carry separate third-party terms.

This notice summarizes that material and does not replace or reproduce the upstream disclaimer. The upstream disclaimer may change; maintainers must re-check the official text before each release and assess whether any change affects NobleDNS redistribution or use. This project does not provide legal advice.


## 9. AdGuard Chinese filter (audit-only)

- Project: AdGuard Content Blocking Filters
- Maintainer: AdGuard
- Filter registry file:
  https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt
- Project repository:
  https://github.com/AdguardTeam/AdguardFilters
- License: GPL-3.0
- License file:
  https://github.com/AdguardTeam/AdguardFilters/blob/master/LICENSE

NobleDNS does not include the AdGuard Chinese filter as a production subscription source. The scheduled audit emits a review-only CSV of simple hostname-pattern candidates derived from the upstream filter, together with source-line provenance and a conservative overlap report. These audit artifacts remain upstream-derived material and are distributed under the applicable GPL-3.0 terms; the included GPL-3.0 license text and upstream attribution apply. The audit does not imply AdGuard endorsement, nor does it approve any candidate for DNS blocking.
