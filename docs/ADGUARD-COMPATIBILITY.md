# AdGuard filter complementarity and compatibility policy

## Purpose

NobleDNS is a DNS-layer blocklist. Its goal is to complement the AdGuard filter ecosystem, not to replace it or claim equivalent capabilities. AdGuard's own documentation distinguishes DNS filtering from browser/app filtering and states that AdGuard DNS Filter is not a replacement for ad-blocking filters.

Official references:
- [AdGuard filters](https://adguard.com/kb/general/ad-filtering/adguard-filters/)
- [AdGuard filter policy](https://adguard.com/kb/general/ad-filtering/filter-policy/)
- [How ad blocking works](https://kb.adguard.com/kb/general/ad-filtering/how-ad-blocking-works/)

## Division of responsibility

| AdGuard filter/function | Primary responsibility | NobleDNS relationship |
|---|---|---|
| Base, Mobile Ads and language-specific filters | Page/request-level ad filtering | Complementary; do not translate cosmetic or page-context rules into domain blocks |
| Tracking Protection | Trackers, analytics scripts, tracking APIs and related page requests | Complementary; block only independently supported DNS hostnames, not entire first-party services by assumption |
| URL Tracking | Remove tracking parameters from URLs | Out of DNS scope; NobleDNS cannot rewrite URLs |
| Social Media | Hide social buttons, embeds and widgets | Out of DNS scope; do not block whole social platforms to hide page widgets |
| Annoyances and its subfilters | Cookie notices, popups, app banners, widgets and other page elements | Out of DNS scope; do not block CMP or widget infrastructure wholesale without evidence of independent unwanted DNS behavior |
| Mail Tracking Protection | Block tracking pixels in email | Complementary only where a dedicated tracking hostname can be safely identified; DNS cannot selectively remove a pixel from message content |
| Filter unblocking search ads and self-promotions | Allow selected contextual search ads and site self-promotion | DNS cannot make URL/context-specific allow decisions; do not broaden allow rules to entire search or platform domains |
| Experimental filter | Test potentially conflicting page-level rules | Not a production DNS source; do not import experimental page rules as domain blocks |
| AdGuard DNS Filter | DNS-compatible domain blocking | Optional DNS-layer supplement, not a requirement for AdGuard client compatibility; currently retained for incremental coverage and subject to overlap/compatibility review |
| Security filters | Malicious/phishing domain protection | Complementary; NobleDNS uses HaGeZi TIF Mini as a compact threat-intelligence add-on, with the same caution about false positives and service dependencies |

## Mandatory compatibility principles

1. **No false equivalence:** DNS hostname blocking cannot perform cosmetic hiding, scriptlet injection, request rewriting, URL parameter removal or page-context decisions.
2. **No broad conversion:** Never convert a URL/path/cosmetic rule into a whole-domain DNS block.
3. **Shared-service caution:** A hostname used for identity, authentication, payment, banking, messaging, push, maps, video, CDN, software delivery or updates must not be blocked solely because one page or app also uses it for advertising or analytics.
4. **First-party caution:** First-party and shared-domain advertising requires hostname- and function-level evidence. Do not block the service's parent domain to remove an ad.
5. **Exception discipline:** Upstream allow rules are provenance, not automatic proof. Keep the exception register, review scope and precedence, and do not import broad exceptions without evidence.
6. **Layered testing:** Test NobleDNS alone, AdGuard page filters alone, and the combined stack where reproducible. Keep resolver, client version, network and test scenario constant.
7. **Honest claims:** Passing syntax or unit tests does not prove compatibility with every AdGuard filter, website, app or client version. Publish only the combinations actually tested.

## Release checks

- The public subscription remains an AdGuard-style DNS list containing hostname rules only.
- Unsupported URL, cosmetic, scriptlet, HTML, modifier and ambiguous syntax is excluded rather than guessed.
- The critical-service regression suite and exception-overlap audits run on every build.
- Newly added sources must have explicit provenance, license attribution, parser-compatibility checks and a documented role.
- TIF Mini is a DNS security feed, not an advertising list; do not treat its presence as proof that every listed domain is currently malicious or as a reason to relax essential-service regression gates.
- The benchmark plan must distinguish DNS-layer outcomes from browser/page-level outcomes.

## Scope limitation

“Compatible with all AdGuard filters” is a design target, not a universal guarantee. AdGuard's filter lists evolve, client implementations differ, and combinations can expose site-specific conflicts. NobleDNS must preserve the division of labor above and expand compatibility evidence over time.
