# Active exception overlap audit

> Snapshot: NobleDNS main build from GitHub Actions run 449 (2026-11-14).
> This is a static scope audit, not a judgment that any exception is justified.

## Reproducible inputs

- Build run: https://github.com/LucentDNS/NobleDNS/actions/runs/43547420485
- NobleDNS compiled subscription SHA-256: `f74394eaa5c85de070bb903f6f08d3976a8a7fb1a70f1e16cb088588691f6bc9`
- AdGuard DNS Filter source SHA-256: `9361c8911858d2067370ec9b460f732f6a7bde3a6d9ae94f18f21ff48b124c2a`
- HaGeZi Multi Normal source SHA-256: `8efb755163dfdb32ce1058a8b8402bbc779ea19ea44b9b310f508bf256ed8b26`
- The 11 exception records remain the frozen legacy pending baseline. Their register records preserve the historical source snapshot from which they were first audited; this report evaluates them against the later run-449 compiled output.

## Findings

The compiled output contains 11 active exception rules. Three intersect at least one blocking rule in this exact snapshot; eight have no overlap with the compiled blocking rules.

| Active exception | Intersecting block rule | Static scope relationship | Review priority |
|---|---|---|---|
| `@@||ad.10010.com^` | `||m1.ad.10010.com^` | Exception is the parent of the blocked subtree; its scope can override the more specific block for that subtree | High |
| `@@||api.ads.tvb.com^` | `||ads.tvb.com^` | Narrow exception host is below a broader blocked parent | Medium |
| `@@||img.ads.tvb.com^` | `||ads.tvb.com^` | Narrow exception host is below a broader blocked parent | Medium |

### Interpretation

- **10010:** the exception is broader than the specific matching block rule. This deserves first review because it may allow more than the single blocked hostname. Do not remove it without establishing whether the parent exception is required and whether a narrower exception would preserve the intended service.
- **TVB:** the blocking rule covers `ads.tvb.com` and its subdomains. The two exceptions are *child-host exceptions* for `api.ads.tvb.com` and `img.ads.tvb.com`; they do not allow the entire parent domain. The earlier shorthand describing these as parent-domain exceptions would be inaccurate.
- **The other eight:** no intersection was found with the current compiled blocking rules. This does not prove that they are necessary, harmless, or safe to delete. Their future value may depend on source changes or client-specific behavior.

The source snapshot places the 11 exception entries together at AdGuard DNS Filter lines 179561–179571. The compiled rule interactions are corroborated by the run-449 source files and manifest; the original register's older source hash/line numbers remain historical provenance, not the line locations in this later snapshot.

## Required next decisions

1. Investigate the 10010 parent exception first; determine whether a narrower exception can preserve the required function.
2. Establish the actual purpose and service impact of the two TVB child exceptions.
3. Review the remaining eight individually for current purpose, evidence and necessity.
4. Test exception precedence on each supported real client before changing any active exception.
5. Keep all 11 marked pending until evidence and review requirements are actually met.

No exception was approved, rejected, removed, or changed by this audit. The public subscription is unchanged by this report.

## Automated audit semantics

`tools/audit_exception_overlaps.py` scans the compiled subscription and emits a row for each active exception, including intersecting block rules and a review priority. It supports only the project's current simple hostname forms. Bare-anchor interactions are labelled as potential overlaps, not proven client behavior. The output is a triage aid; it cannot establish why an exception exists or how every DNS client resolves precedence.
