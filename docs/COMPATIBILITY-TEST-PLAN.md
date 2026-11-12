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
- `notbare.nobledns.test`
- `subonly.nobledns.test`
- `child.subonly.nobledns.test`
- `exception.nobledns.test`
- `www.exception.nobledns.test`
- `exact.nobledns.test`
- `www.exact.nobledns.test`
- `endanchor.nobledns.test`
- `www.endanchor.nobledns.test`
- `endanchor.nobledns.test.evil.test`
- `exactblock.nobledns.test`
- `www.exactblock.nobledns.test`

The authoritative server should return a known test address for every name in both zones. This separates filtering behavior from upstream resolution failures.

## Rule fixtures

Use a dedicated temporary custom list containing only these synthetic rules:

```text
||apex.nobledns.test^
||bare.nobledns.test
.subonly.nobledns.test^
||exception.nobledns.test^
@@||exception.nobledns.test^|
||exact.nobledns.test^
@@|exact.nobledns.test^|
||endanchor.nobledns.test^|
|exactblock.nobledns.test^
```

Do not add these synthetic rules to the public subscription.

## Test cases

| Rule | Query | Expected interpretation |
|---|---|---|
| `||apex.nobledns.test^` | apex | Block |
| `||apex.nobledns.test^` | `www.apex.nobledns.test` | Block |
| `||apex.nobledns.test^` | `deep.www.apex.nobledns.test` | Block |
| `||bare.nobledns.test` | apex | Block |
| `||bare.nobledns.test` | `child.bare.nobledns.test` | Block |
| `||bare.nobledns.test` | `bare.nobledns.test.evil.test` | Expected to match: the hostname starts with the anchored pattern and no `^` end separator is present; verify in client |
| `||bare.nobledns.test` | `notbare.nobledns.test` | Must not be blocked by a hostname-start anchor |
| `.subonly.nobledns.test^` | apex | Allow |
| `.subonly.nobledns.test^` | `child.subonly.nobledns.test` | Block |
| `@@||exception.nobledns.test^|` | apex | Allow |
| `@@||exception.nobledns.test^|` | `www.exception.nobledns.test` | Allow |
| `@@|exact.nobledns.test^|` | apex | Allow |
| `@@|exact.nobledns.test^|` | `www.exact.nobledns.test` | Block; the single leading `|` and trailing `|` restrict the exception to the exact hostname |
| `||endanchor.nobledns.test^|` | apex and subdomain | Block |
| `||endanchor.nobledns.test^|` | `endanchor.nobledns.test.evil.test` | Allow; the trailing `|` requires the hostname to end at the pattern |
| `|exactblock.nobledns.test^` | apex | Block |
| `|exactblock.nobledns.test^` | `www.exactblock.nobledns.test` | Allow; the single leading `|` and `^` restrict the block to the exact hostname |

For each query, record the DNS response, client filtering log, authoritative-server log and whether the result matches the documented semantics. A timeout or missing authoritative response is an invalid test, not a successful block.

The bare-anchor and end-anchored exception cases verify the documented distinction between hostname-start anchoring, the `^` hostname-end separator, the single-pipe start/end anchors, and exact-host block scope. AdGuard documents these forms in its [DNS filtering syntax reference](https://adguard-dns.io/kb/general/dns-filtering-syntax/). In particular, a hostname continuing after the literal pattern is expected to match when `^` is absent. Record actual client results and do not rewrite upstream rules based on a single client result.

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
