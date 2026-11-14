# Feedback and rule improvement

Use GitHub Issues and the False positive template for broken sites/apps. Report exact hostnames, affected feature, DNS client/version, reproduction steps and sanitized DNS evidence. Do not post personal identifiers, tokens, account data or full private DNS logs.

Triage:

1. Reproduce with NobleDNS enabled and disabled, keeping the resolver and other settings constant.
2. Confirm the exact queried hostname and whether the main list contains a matching rule.
3. Determine whether the issue is a false positive, upstream service dependency, client-format problem, or unrelated network failure.
4. If confirmed, add a narrowly scoped regression case and document evidence before changing the rules.
5. Prefer removing or narrowing the offending block only when evidence supports it. Avoid broad allowlists that weaken unrelated protection.
6. Run the complete regression suite and publish a changelog note with the fix.

Missed-block reports should include the exact hostname, page/app context and evidence that the hostname is advertising/tracking/malicious. A domain's name alone is not sufficient evidence.


## What maintainers do after a report

Routine upstream refreshes are automated by the scheduled build workflow. It runs three times daily (02:23, 10:23 and 18:23 China Standard Time), rebuilds from the four approved sources, runs regression and quality gates, and publishes changed subscription artifacts to the default branch only after validation. Daily data refreshes update the main-branch subscription only; they do not create or retarget SemVer releases. Published release assets remain point-in-time snapshots and are not refreshed by routine builds.

For users, the intended steady state is simple: report a reproducible issue; maintainers handle verification and correction. A report is not automatically converted into a rule change. The maintainer will:

- verify the exact hostname, matching rule and affected function;
- reproduce with NobleDNS on/off under otherwise identical DNS conditions;
- consult upstream provenance and independent evidence;
- choose the narrowest justified removal, exception or addition;
- add a regression test and run the full build/quality gates;
- publish the validated correction with a changelog note.

Unverified reports, broad domain allowlist requests and hostname-name guesses do not trigger production changes. This protects the list from weakening protection or breaking unrelated services in response to an isolated, unconfirmed claim.
