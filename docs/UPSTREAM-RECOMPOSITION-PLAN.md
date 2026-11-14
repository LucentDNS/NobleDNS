# Upstream recomposition and regional DNS review

> Status: research plan; no production source or subscription behavior is changed by this document.

## Objective

Re-evaluate NobleDNS from a clean baseline. The goal is not to maximize upstream count or rule count. Every source must demonstrate incremental value against a reproducible comparator set, without losing rule semantics or creating unacceptable compatibility risk.

## Baseline candidate

Use the upstream-designed pair as the first compact baseline:

- HaGeZi Pro Mini: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.mini.txt
- HaGeZi TIF Mini: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt

Treat this as a candidate baseline, not an approved production switch. Verify the exact upstream path, snapshot, license/notice requirements, supported syntax, byte size, and parsed rule count before use. Do not combine Pro Mini with another HaGeZi Multi tier. TIF Mini is a distinct threat-intelligence supplement.

## Regional DNS inputs: avoid duplicate imports

Regional Chinese advertising coverage must be evaluated, but browser filters must not be flattened into DNS rules.

### AdGuard Chinese filter

The full filter at https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt contains cosmetic, URL, regex, request-context, exception, and hostname rules. Only explicitly DNS-suitable hostname material can be considered. Preserve source section, line, modifiers, exclusions, and rationale in the audit.

### EasyList China and the HostlistCompiler China example

The official example is named "EasyList China ad servers" and is a deliberately narrow extraction, not a full conversion of EasyList China. Its configuration:
- selects the EasyList China Adblock source;
- excludes lines outside the full-domain block/exception shape;
- excludes $third-party-scoped rules before modifier removal;
- then applies RemoveModifiers and Validate;
- applies Deduplicate and Compress globally.

Do not generalize this recipe to arbitrary browser filters. In particular, never strip $third-party from rules that were not first proven to meet the example's narrow inclusion/exclusion policy. Retain exceptions and provenance for review; do not assume every extracted hostname is safe to block globally.

### Existing AdGuard DNS Filter

AdGuard DNS Filter's own build configuration already imports DNS-oriented Chinese ad-server sections and a narrow EasyList China extraction with shared exclusions and transformations. Therefore, adding the full Chinese filter or EasyList China wholesale beside AdGuard DNS Filter risks duplication and semantic loss.

The current NobleDNS audit reports that the supported hostname subset of the reviewed AdGuard DNS Filter snapshot is already covered by the current production subscription. This is a snapshot-specific syntactic result, not proof of quality or real-world effectiveness. Re-run the comparison against the Pro Mini + TIF Mini candidate before deciding whether AdGuard DNS Filter contributes any unique, justified regional or general-purpose coverage.

## Required comparison matrix

Build isolated, immutable snapshots and compare at least:

1. HaGeZi Pro Mini alone.
2. HaGeZi Pro Mini + TIF Mini.
3. HaGeZi Pro Mini + TIF Mini + AdGuard DNS Filter.
4. Candidate 2 plus the official HostlistCompiler EasyList China DNS extraction.
5. Candidate 2 plus independently extracted DNS-suitable AdGuard Chinese candidates, with exclusions preserved.
6. Candidate 2 plus the regional additions from 4 and 5 after semantic and overlap review.
7. Current NobleDNS production snapshot.
8. Independent comparators: HaGeZi Pro, AdGuard DNS Filter, OISD Big, and anti-AD AdGuard.

Do not stack lists for the primary efficacy comparison. Run each candidate in isolation against the same corpus and resolver/client environment.

## Required measurements

For every snapshot record:
- upstream commit/ref, retrieval timestamp, URL, license/attribution, bytes, SHA-256;
- raw lines, accepted blocking rules, exceptions, unsupported syntax and exclusion reasons;
- exact duplicates and semantic overlaps (including parent/subdomain coverage);
- rules unique to each source and candidate;
- DNS-client-supported syntax and preserved modifier/exception semantics;
- independently reviewed positive and negative corpus results;
- real client task results and operational cost where available.

A list's unique rule count is a discovery metric, not a quality score. Do not add a unique rule merely because it is absent from another list.

## Acceptance policy

- No production source change until the candidate build is reproducible and passes syntax, provenance, license, regression and output-integrity checks.
- No regional source is accepted solely because it is Chinese-language or popular.
- No browser-only cosmetic, URL, regex, scriptlet, platform, or request-context rule is converted to a global DNS block.
- No modifier is removed unless the exact source-selection policy proves the modifier's scope is intentionally excluded and the behavior is documented.
- Every project-authored exception requires evidence, narrow scope, review record and regression coverage.
- A critical-service false positive blocks release until explained and corrected.
- If a compact upstream baseline already performs as well as a larger composition on the reviewed corpus, prefer the compact baseline.
- Report limitations honestly: static comparisons and CI success do not prove real-world efficacy, false-positive rate, latency, or compatibility.

## Expected outcome

Select the smallest defensible composition that meets the project's coverage and compatibility requirements. If no independent evidence shows that an additional source improves the result, omit it. Keep the current production subscription unchanged until the comparison provides a defensible migration decision.
