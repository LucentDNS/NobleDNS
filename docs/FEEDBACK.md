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
