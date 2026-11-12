# DNS rule lifecycle and dead-domain review

## Purpose

A rule can remain in an upstream feed after its hostname stops resolving, is sinkholed, expires, or changes ownership. Conversely, a temporary DNS failure does not mean a hostname is dead. NobleDNS therefore treats DNS liveness as a time-bounded observation, not a permanent property.

This process is a **review aid**, not an automatic rule-removal mechanism. The current public build remains driven by the two approved upstream lists. No rule is removed solely because it returned NXDOMAIN.

## What the statuses mean

The offline tool `tools/audit_rule_liveness.py` consumes:

- the exact generated `dns-filter.txt` being reviewed;
- a versioned JSON file of externally collected DNS observations, including the exact HTTPS/DoT resolver endpoint for every observation;
- the exact source snapshots and `sources-manifest.json` from the same build (required by the CLI).

It verifies source snapshot SHA-256 values and records which approved source(s) still contain each observed hostname. Subscription membership and source attribution are suffix-aware: an observed subdomain is attributed to an exact blocking rule or any matching parent-domain rule, rather than being incorrectly treated as outside the subscription merely because the full hostname is not itself a literal rule.

| Status | Meaning | Action |
|---|---|---|
| `active_dns_answer_observed` | At least one fresh A/AAAA query returned an answer | Not a dead-domain candidate |
| `mixed_or_split_horizon` | Fresh positive and NXDOMAIN observations coexist | Investigate resolver, geography, CDN and split-horizon differences |
| `stable_nxdomain_candidate_manual_review` | Strict multi-resolver, multi-vantage, multi-day NXDOMAIN threshold met, with a relevant SOA authority record on every latest response | Manual review only; never auto-delete |
| `nxdomain_without_authority_soa_manual_review` | NXDOMAIN quorum appears met, but at least one latest response lacks a relevant SOA authority record | Investigate possible resolver-side synthesis/filtering; not a stable dead-domain finding |
| `nxdomain_authority_zone_disagreement_manual_review` | Latest NXDOMAIN responses contain multiple or inconsistent SOA zones | Investigate delegation, split-horizon behavior or resolver-side synthesis; not a stable dead-domain finding |
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
3. At least three distinct resolver operators are represented, and **each qualifying operator must be observed from at least two genuinely distinct vantage points**. Resolver ownership and vantage geography must be independently verified; labels alone are not proof.
4. At least three resolver/operator/vantage combinations have both A and AAAA results, and every represented pair must have complete A/AAAA coverage.
5. **Every resolver/operator/vantage pair in the quorum** has at least two complete UTC-day rounds, each containing NXDOMAIN for both A and AAAA, with the A and AAAA responses no more than 15 minutes apart and no conflicting or failed response for either qtype that day. That pair's own first-to-last complete-round span must be at least seven full elapsed days. A historical result from one pair cannot extend the observation window of a newer quorum formed by other pairs.
6. Every latest NXDOMAIN response includes exactly one relevant SOA authority zone that is an ancestor of the queried hostname, and that zone is consistent across the full resolver/vantage quorum. Missing or inconsistent SOA evidence receives a separate manual-review status, never a stable candidate.
7. Observations are no older than 30 days by default.
8. Observation timestamps cannot be in the future. A/AAAA answers must be syntactically valid IP addresses of the queried address family; non-NOERROR responses cannot carry address answers.

The threshold is intentionally conservative. It reduces the chance that one resolver outage, one region, one query type, or one short-lived DNS change is mistaken for a dead domain. It does not prove that the domain is malicious, unregistered, abandoned, or safe to unblock.

Resolvers and vantage points must be genuinely independent. Do not count multiple endpoints operated by the same provider as independent operators. A single CI runner is not multiple geographic vantage points. The tool validates stable resolver-ID-to-endpoint mapping and rejects one endpoint hostname claimed by multiple operator labels. Vantage labels are normalized by trimming whitespace and case-folding so cosmetic label variations cannot inflate the number of sites. It still cannot cryptographically prove provider ownership or geographic independence; those facts must be independently verified and documented by the collector/reviewer before evidence is accepted.

## Reproducible pilot sample

A deterministic, source-stratified 20-hostname sample is available at [`docs/audits/2026-11-12-liveness-pilot-sample.txt`](audits/2026-11-12-liveness-pilot-sample.txt). Its source membership, SHA-256 provenance, sampling seed and limitations are documented in the adjacent [sample report](audits/2026-11-12-liveness-pilot-sample.md). It contains 10 hostnames shared by both approved sources, 5 AdGuard-only and 5 HaGeZi-only. All 20 were verified in the 2026-11-12 NobleDNS 1.0.3 build artifact.

Use this sample for a controlled pilot, not as a dead-domain list. It is too small to estimate overall list health and no result from it can authorize a rule removal.

## Controlled observation collection

The companion `tools/collect_dns_liveness.py` performs the network queries; the audit tool above remains offline. The collector accepts only an explicit newline-separated sample file and a resolver configuration. It never reads or probes the complete subscription automatically.

The example resolver configuration uses four independent operators to improve the chance of obtaining a three-operator quorum from Mainland and international vantage points:

- Tencent DNSPod Public DNS DoH: `https://doh.pub/dns-query`
- Cloudflare standard public DNS DoH: `https://cloudflare-dns.com/dns-query`
- Google Public DNS DoH: `https://dns.google/dns-query`
- Quad9 unfiltered DoT: `tls://dns10.quad9.net:853` (the 9.9.9.10 service family does not apply threat blocking)

Tencent's official documentation publishes the DNSPod DoH/DoT endpoints, a 20 QPS per-domain limit, and no SLA for the free service. The collector's default 0.5-second inter-query delay stays well below that limit. Cloudflare and Google document RFC 8484 wire-format DoH; Quad9 documents the unfiltered DoT service and endpoint. References: [Tencent DNSPod Public DNS](https://cloud.tencent.cn/document/product/302/110786), [Cloudflare DoH wire format](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-wireformat/), [Google Public DNS DoH](https://developers.google.com/speed/public-dns/docs/doh), [Quad9 service addresses](https://docs.quad9.net/services/).

The example deliberately does not count security-filtering resolvers as neutral evidence. 360 Safe DNS's own product page describes threat-intelligence-backed security features, so its response policy needs separate verification before it could be admitted to a dead-domain quorum. We also do not hard-code a generic AliDNS hostname: current Alibaba HTTPDNS documentation describes account-configured DoH endpoints, so a usable public endpoint must be verified before inclusion.

Example PowerShell invocation (run once per day from each location; the timestamp prevents overwriting earlier observations):

```powershell
$stamp = Get-Date -Format "yyyy-MM-dd-HHmmss"
py -3.12 .\tools\collect_dns_liveness.py `
  --sample .\docs\audits\2026-11-12-liveness-pilot-sample.txt `
  --resolvers .\tools\dns-liveness-resolvers.example.json `
  --vantage "site-a" `
  --output ".\private-audit\observations-site-a-$stamp.json"
```

At the second genuinely different location, use the same sample and resolver configuration, change `--vantage` to `site-b`, and use the corresponding `observations-site-b-$stamp.json` output name. Repeat on dates spanning at least seven full days. **Do not reuse a fixed output filename:** the collector writes a new document and will overwrite an existing file at that path.

After collecting all daily files, merge them without altering individual observations. This PowerShell example writes UTF-8 without a BOM so Python's JSON reader can consume it:

```powershell
$files = Get-ChildItem -LiteralPath .\private-audit -Filter "observations-*.json" -File |
  Where-Object { $_.Name -ne "observations-merged.json" } |
  Sort-Object Name
if (-not $files) { throw "No daily observation files found." }
$all = foreach ($file in $files) {
  $doc = Get-Content -Raw -Encoding UTF8 $file.FullName | ConvertFrom-Json
  if ($doc.schema_version -ne 1) { throw "Unsupported observation schema: $($file.Name)" }
  $doc.observations
}
$merged = [ordered]@{ schema_version = 1; observations = @($all) }
$json = $merged | ConvertTo-Json -Depth 12
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$out = Join-Path (Get-Location) "private-audit\observations-merged.json"
[System.IO.File]::WriteAllText($out, $json + [Environment]::NewLine, $utf8NoBom)
```

The collector has hard bounds: at least 3 unique resolver operators, at most 10 configured resolvers, at most 50 hostnames per run (default 20), 2–20 second timeout, and 0.2–5 second delay between requests. It queries only A and AAAA and uses DNS-over-HTTPS/TLS wire format. It records response codes, address answers, CNAME targets, negative SOA authority zones, resolver endpoint and the DNSSEC AD bit. No retries or bulk subscription scans are performed. The DoH client bypasses ambient HTTP proxy settings so a configured proxy cannot silently impersonate the selected resolver; DoT uses a direct TLS socket with certificate validation.

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
