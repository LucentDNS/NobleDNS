# DNS rule lifecycle and dead-domain review

## Purpose

A rule can remain in an upstream feed after its hostname stops resolving, is sinkholed, expires, or changes ownership. Conversely, a temporary DNS failure does not mean a hostname is dead. NobleDNS therefore treats DNS liveness as a time-bounded observation, not a permanent property.

This process is a **review aid**, not an automatic rule-removal mechanism. The current public build remains driven by the two approved upstream lists. No rule is removed solely because it returned NXDOMAIN.

## What the statuses mean

The offline tool `tools/audit_rule_liveness.py` consumes:

- the exact generated `dns-filter.txt` being reviewed;
- a versioned JSON file of externally collected DNS observations, including the exact HTTPS/DoT resolver endpoint for every observation;
- the exact source snapshots and `sources-manifest.json` from the same build (required by the CLI).

It verifies source snapshot SHA-256 values and records which approved source(s) still contain each observed hostname.

| Status | Meaning | Action |
|---|---|---|
| `active_dns_answer_observed` | At least one fresh A/AAAA query returned an answer | Not a dead-domain candidate |
| `mixed_or_split_horizon` | Fresh positive and NXDOMAIN observations coexist | Investigate resolver, geography, CDN and split-horizon differences |
| `stable_nxdomain_candidate_manual_review` | Strict multi-resolver, multi-vantage, multi-day NXDOMAIN threshold met | Manual review only; never auto-delete |
| `insufficient_nxdomain_evidence` | NXDOMAIN observed but quorum/time coverage is insufficient | Gather more observations |
| `nodata_or_no_address` | NOERROR without A/AAAA address data | Not equivalent to NXDOMAIN; investigate record type and CNAME behavior |
| `sinkhole_observed_manual_review` | An observation carries a separately sourced sinkhole evidence URL | Retain pending security/context review; sinkhole is not dead |
| `cname_chain_observed_manual_review` | A CNAME target was observed without a final A/AAAA answer | Investigate the alias chain and target; do not call the queried hostname dead |
| `inconclusive_dns_error` | SERVFAIL, REFUSED, FORMERR, TIMEOUT or other DNS errors | Do not classify as dead |
| `stale_or_missing_observations` | No observations inside the configured freshness window | No liveness conclusion |

The report also marks whether the hostname is in the current subscription and lists the source keys that contain it. Historical observations for a hostname no longer in the subscription are informational and cannot trigger a deletion.

## Minimum NXDOMAIN screening threshold

A hostname is labelled `stable_nxdomain_candidate_manual_review` only when all of the following hold:

1. Fresh observations exist for both A and AAAA.
2. The latest observation for every resolver/operator/vantage/qtype tuple is NXDOMAIN.
3. At least three distinct resolver operators are represented.
4. At least two distinct vantage points are represented.
5. At least three resolver/operator/vantage combinations have both A and AAAA results.
6. The fresh NXDOMAIN observation history spans at least seven full elapsed days.
7. Observations are no older than 30 days by default.
8. Observation timestamps cannot be in the future. A/AAAA answers must be syntactically valid IP addresses of the queried address family; non-NOERROR responses cannot carry address answers.

The threshold is intentionally conservative. It reduces the chance that one resolver outage, one region, one query type, or one short-lived DNS change is mistaken for a dead domain. It does not prove that the domain is malicious, unregistered, abandoned, or safe to unblock.

Resolvers and vantage points must be genuinely independent. Do not count multiple endpoints operated by the same provider as independent operators. A single CI runner is not multiple geographic vantage points. The tool can validate the labels and observation structure, but it cannot cryptographically prove operator ownership or geographic independence; that verification must be documented by the collector/reviewer before evidence is accepted.

## Controlled observation collection

The companion `tools/collect_dns_liveness.py` performs the network queries; the audit tool above remains offline. The collector accepts only an explicit newline-separated sample file and a resolver configuration. It never reads or probes the complete subscription automatically.

The example resolver configuration uses three independent operators:

- Cloudflare DoH: `https://cloudflare-dns.com/dns-query`
- Google Public DNS DoH: `https://dns.google/dns-query`
- Quad9 unfiltered DoT: `tls://dns10.quad9.net:853` (the 9.9.9.10 service family does not apply threat blocking)

Cloudflare and Google document RFC 8484 wire-format DoH; Quad9 documents the unfiltered DoT service and endpoint. References: [Cloudflare DoH wire format](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-wireformat/), [Google Public DNS DoH](https://developers.google.com/speed/public-dns/docs/doh), [Quad9 service addresses](https://docs.quad9.net/services/).

Example PowerShell invocation:

```powershell
py -3.12 .\tools\collect_dns_liveness.py `
  --sample .\private-audit\review-sample.txt `
  --resolvers .\tools\dns-liveness-resolvers.example.json `
  --vantage "operator-assigned-location-label" `
  --output .\private-audit\observations.json
```

The collector has hard bounds: at least 3 unique resolver operators, at most 10 configured resolvers, at most 50 hostnames per run (default 20), 2–20 second timeout, and 0.2–5 second delay between requests. It queries only A and AAAA and uses DNS-over-HTTPS/TLS wire format. It records response codes, address answers, CNAME targets, resolver endpoint and the DNSSEC AD bit. No retries or bulk subscription scans are performed. The DoH client bypasses ambient HTTP proxy settings so a configured proxy cannot silently impersonate the selected resolver; DoT uses a direct TLS socket with certificate validation.

Run the same small sample from at least two genuinely different network locations, changing the `--vantage` label. A label is self-reported: the collector cannot prove the machine's geography, resolver ownership, or independence. Verify those facts separately and document the evidence. Public resolvers see the queried hostnames and the collector's network source address; do not include private hostnames or private traffic logs. Keep raw observations private until reviewed and sanitized.

## What must happen before a removal proposal

For every stable NXDOMAIN candidate that is still in the public subscription:

1. Verify the hostname and its source provenance against the exact snapshot hashes.
2. Check the upstream source's current purpose, history, removal policy and any available last-seen or threat-context evidence.
3. Review CNAME chains, A/AAAA, DNSSEC status where available, and authoritative responses. Distinguish NXDOMAIN from NODATA, SERVFAIL, timeout, REFUSED and resolver-side filtering.
4. Check whether the name is registered, expired, newly registered, parked, sinkholed, or potentially reassigned. RDAP/WHOIS status alone is not proof of benign ownership or malicious intent.
5. Consider whether the domain is a known threat sinkhole, an intentionally dormant tracking endpoint, a temporary campaign endpoint, or a shared/vendor service.
6. Require a second maintainer review for a project-authored removal or allowlist change.
7. Add a regression case and document the evidence, confidence, review date, scope and rollback plan.

If the source still lists the hostname but NobleDNS lacks evidence to override the source, keep it in the upstream-derived subscription and record the unresolved review. If every configured upstream removes it, the normal source diff and drift gates still apply.

## Explicit non-goals and safety rules

- No DNS queries are sent by this tool. It is deliberately offline and consumes reviewed observations.
- Do not upload private household, customer, employee or device DNS logs. Collect only controlled, minimized observations with no client identifiers.
- Do not treat a failed query, timeout, SERVFAIL, empty NOERROR response, or one resolver's NXDOMAIN as proof of a dead domain.
- Do not treat a sinkhole IP as proof that the hostname is harmless or should be removed.
- Do not infer ownership change from a changed IP address or shared hosting.
- Do not automatically delete, expire, unblock, or rewrite any rule. `automatic_removals` is hard-coded to zero.
- Do not publish the raw DNS observations if they contain private operational details. The reviewed report can be published only after privacy and provenance review.

## Running the audit

The daily build workflow runs the tool against an intentionally empty fixture. This verifies the pipeline and records that no liveness evidence has yet been collected; it is **not** a claim that all rules are live or that no dead rules exist.

For a controlled offline review, place a reviewed observation document in a private working directory and run:

```powershell
py -3.12 .\tools\audit_rule_liveness.py `
  --rules .\build-output\latest\dns-filter.txt `
  --observations .\private-audit\dns-liveness-observations.json `
  --source-dir .\build-output\latest\sources `
  --output-dir .\private-audit\liveness-report
```

Review `report.json` and `candidates.csv`. The `stable_nxdomain_candidate_manual_review` status is a lead for human investigation, never an approval to delete a rule.
