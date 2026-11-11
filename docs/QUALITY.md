# Quality and acceptance policy

## User-facing quality target

NobleDNS should be no worse than established DNS blocklists in practical blocking coverage while maintaining a low false-positive rate. This is a target to demonstrate with evidence, not a claim inferred from rule count.

## Required quality dimensions

1. **Blocking coverage:** representative ad, tracking, telemetry and known malicious-domain test sets.
2. **False positives:** critical first-party services, authentication, payment, banking, messaging, push, app updates, video/CDN and domestic services.
3. **Compatibility:** AdGuard Android, AdGuard Home and other explicitly supported clients.
4. **Reliability:** repeatable builds, strict source validation, stable subscription format, bounded resource use.
5. **Change safety:** source hash/count tracking, drift gates, regression corpus and release rollback.

## Current parser scope

The compiler supports `||domain^`, `||domain` and `@@||domain^` when the hostname is a valid multi-label DNS name. Bare domain-anchor rules are preserved exactly. Exceptions are not placed in the main list. Wildcards, modifiers, regex/path patterns, IP literals, trailing-dot/open suffix patterns and other unsupported syntax are excluded and recorded.

Do not expand parser scope unless tests prove semantic equivalence for the target clients. Do not silently turn unsupported patterns into ordinary domain blocks.

## Release gates

- Exactly the two approved sources load successfully and decode as strict UTF-8.
- Each source exceeds configured minimum size and parsed-block count.
- Per-source parsed rule count does not drift more than 15% from the last published manifest without review/override.
- Main output has valid supported syntax, no duplicates, nonzero rules and no more than 500,000 rules.
- Regression tests pass.
- Release is created only when the main list SHA256 changes.
- Stable release channel remains disabled until real-world client and false-positive testing is documented.

## Promotion to stable

Before changing `release_channel` from `candidate` to `stable`, record test results for supported clients, critical service checks, false-positive reports, missed-block checks, and a rollback procedure. A successful build alone is insufficient.
