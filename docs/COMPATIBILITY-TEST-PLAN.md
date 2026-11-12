# DNS client compatibility test plan

## Purpose

This plan defines how NobleDNS will verify rule behavior in real DNS filtering clients. It is a test procedure, not a claim that the listed clients or cases have already passed.

Use an isolated test environment and a locally controlled authoritative DNS zone. Do not use production advertising, banking, payment, messaging or other third-party domains as test targets.

## Target clients

| Client | Version | Platform | Status | Evidence |
|---|---|---|---|---|
| AdGuard for Android | Record at test time | Android | NOT TESTED | — |
| AdGuard Home | Record at test time | Record at test time | NOT TESTED | — |

Add another client only when its support for the exact NobleDNS rule syntax is documented. Do not imply compatibility with generic hosts-only DNS resolvers.

## Controlled test zone

Use locally hosted authoritative zones under the reserved `.test` TLD, including `nobledns.test` and `evil.test`. Configure the test client to use these zones only in an isolated lab.

Create controlled records for:

- `apex.nobledns.test`
- `www.apex.nobledns.test`
- `deep.www.apex.nobledns.test`
- `bare.nobledns.test`
- `child.bare.nobledns.test`
- `bare.nobledns.test.evil.test`
- `x.bare.nobledns.test.evil.test`
- `notbare.nobledns.test`
- `exception-parent.nobledns.test`
- `allow.exception-parent.nobledns.test`
- `deep.allow.exception-parent.nobledns.test`
- `allowed.nobledns.test`
- `child.allowed.nobledns.test`
- `subonly.nobledns.test`
- `child.subonly.nobledns.test`
- `subonly-bare.nobledns.test`
- `child.subonly-bare.nobledns.test`
- `child.subonly-bare.nobledns.test.evil.test`

The authoritative server should return a known test address for every name in both zones. This separates filtering behavior from upstream resolution failures.

## Rule fixtures

Use a dedicated temporary custom list containing only these synthetic rules:

```text
||apex.nobledns.test^
||bare.nobledns.test
||exception-parent.nobledns.test^
@@||allow.exception-parent.nobledns.test^
||child.allowed.nobledns.test^
@@||allowed.nobledns.test^
.subonly.nobledns.test^
.subonly-bare.nobledns.test
```

The exception cases deliberately use only the project's currently supported simple exception form, `@@||domain^`. Do not add modifiers such as `$important`; the production parser excludes them, and AdGuard documents that `$important` can override ordinary exception rules. See the [AdGuard DNS filtering syntax reference](https://adguard-dns.io/kb/general/dns-filtering-syntax/).

The two leading-dot rules are compatibility probes only, not production syntax. An archived 2023 AdGuard Android/AdGuard Home article documents `.example.org` as subdomains-only, while the current DNS-specific reference no longer lists that pattern. Test both caret and non-caret variants on the exact supported client versions before considering any parser change. See the [archived AdGuard KB](https://github.com/AdguardTeam/AdguardKnowledgeBase/blob/master/01.general/19.dns-filtering-syntax/docs.en.md).

Do not add these synthetic rules to the public subscription.

## Test cases

| Rule | Query | Expected interpretation |
|---|---|---|
| `||apex.nobledns.test^` | apex | Block |
| `||apex.nobledns.test^` | `www.apex.nobledns.test` | Block |
| `||apex.nobledns.test^` | `deep.www.apex.nobledns.test` | Block |
| `||bare.nobledns.test` | apex | Block |
| `||bare.nobledns.test` | `child.bare.nobledns.test` | Block |
| `||bare.nobledns.test` | `bare.nobledns.test.evil.test` | Potential match: no explicit hostname-end boundary; record actual client result |
| `||bare.nobledns.test` | `x.bare.nobledns.test.evil.test` | Potential match after a subdomain label; record actual client result |
| `||bare.nobledns.test` | `notbare.nobledns.test` | Must not be blocked by a hostname-start anchor |
| `||exception-parent.nobledns.test^` | apex | Block |
| `||exception-parent.nobledns.test^` | `allow.exception-parent.nobledns.test` | Would block in isolation; expected final result is Allow after the narrower exception |
| `@@||allow.exception-parent.nobledns.test^` | `deep.allow.exception-parent.nobledns.test` | Allow |
| `||child.allowed.nobledns.test^` | `child.allowed.nobledns.test` | Would block in isolation; expected final result is Allow after the parent exception |
| `@@||allowed.nobledns.test^` | apex | Allow |
| `@@||allowed.nobledns.test^` | `child.allowed.nobledns.test` | Allow; the parent exception overrides the child block |
| `.subonly.nobledns.test^` | apex | Allow |
| `.subonly.nobledns.test^` | `child.subonly.nobledns.test` | Block |
| `.subonly-bare.nobledns.test` | apex | Allow |
| `.subonly-bare.nobledns.test` | `child.subonly-bare.nobledns.test` | Block if legacy leading-dot behavior remains supported |
| `.subonly-bare.nobledns.test` | `child.subonly-bare.nobledns.test.evil.test` | Record observed result; no explicit hostname-end boundary |

For each query, record the DNS response, client filtering log, authoritative-server log and whether the result matches the documented semantics. A timeout or missing authoritative response is an invalid test, not a successful block.

The bare-anchor cases distinguish two concepts: `||` anchors a match at the hostname start or a subdomain boundary, while the absence of `^` means there is no explicit hostname-end boundary. AdGuard's syntax reference defines `||` as a hostname anchor and `^` as the hostname-end separator. Therefore the synthetic cases containing an additional suffix are treated as potential matches, not assumed safe. Record actual behavior on each supported client and do not rewrite upstream rules based on a single client result.

The exception cases verify the documented basic exception form against both an exact hostname and its descendants. They do not verify precedence involving modifiers, because modified exceptions are not part of the published NobleDNS syntax.

## Execution procedure

1. Record the client name, exact version, OS version, date and test-zone configuration.
2. Confirm every test name resolves successfully when filtering is disabled.
3. Add the temporary fixture list and wait for the client to load it.
4. Run every query at least three times after clearing or expiring relevant caches.
5. Save sanitized client logs and authoritative DNS logs.
6. Repeat with filtering disabled to confirm the test zone itself is healthy.
7. Compare results with the expected interpretation and document any client-specific differences.
8. Link the evidence from the compatibility matrix before changing a status from NOT TESTED.

## Result record

For every completed run, record:

- Client and exact version
- OS and device/platform
- Test date and operator
- Fixture file SHA-256
- Test-zone configuration
- Per-query response and filtering decision
- Client and authoritative-server log references
- Pass/fail/blocked-by-environment result
- Known limitations and follow-up issue

Never publish private IP addresses, device identifiers, account details or unredacted DNS logs.

## Acceptance criteria

A client is marked **VERIFIED FOR TESTED SYNTAX** only when all applicable cases have reproducible results and no unexplained mismatch remains. This status applies only to the tested client version and tested syntax forms; it is not a blanket guarantee for all applications, websites or future versions.

A client is marked **PARTIAL** when some forms are verified but others are unsupported or unresolved. Keep it **NOT TESTED** when evidence is absent.

## Scope limits

This procedure tests rule matching and client behavior. It does not measure advertising coverage, malware detection rates, false-positive rates on the public internet, or the quality of upstream source classifications. Those require a separate reviewed real-world corpus and independent evidence.
