# NobleDNS DNS liveness pilot sample (v1)

## Purpose

A small, reproducible, source-stratified sample for the first controlled DNS-liveness collection pilot. All 20 hostnames were verified in the NobleDNS 1.0.3 build artifact generated on 2026-11-12. This is a measurement sample only; it does not assert that any hostname is dead, malicious, or safe to unblock.

## Sampling method

- Build: NobleDNS 1.0.3, built at 2026-11-12T07:55:37Z.
- Generated unique blocking hostnames: 303,609.
- Sample size: 20.
- Deterministic seed: `NobleDNS-1.0.3-liveness-pilot-2026-11-12`.
- Strata: 10 present in both approved source snapshots; 5 present only in AdGuard DNS Filter; 5 present only in HaGeZi Multi NORMAL.
- Within each stratum, domains were ordered by SHA-256 of `seed + ":" + hostname`, and the first required count was selected.
- Every selected hostname was checked against the exact source snapshots and the generated `dns-filter.txt`.

## Snapshot provenance

| Artifact | SHA-256 |
|---|---|
| Generated subscription | `b40eb4ce3f1ce56dd1d1309020931018f527a5138bcdf554b4b92bc629231529` |
| AdGuard DNS Filter | `64e6f3269b35a3103d95d5e4f15e9b361baab5bc59d2ced584f565376debe5eb` |
| HaGeZi Multi NORMAL | `36b07747c4df85cf7ad2bddc2d0c47b46aa26640f253592633542c0dcd0ebd8f` |

## Limitations and handling

- This small sample is not a prevalence estimate and cannot justify deleting or allowlisting any rule.
- Source membership is provenance, not independent evidence of the hostname's current function.
- Run from at least two independently verified network locations, repeat over at least seven full days, and preserve raw observations privately.
- Public DNS resolvers will see the queried hostnames and the collector's network source address.
- Only the conservative liveness classifier may label a stable NXDOMAIN manual-review candidate. Every candidate still requires registration/reassignment, sinkhole, authoritative context, upstream history, compatibility and second-maintainer review.
- Do not modify the production source configuration or public subscription based on this pilot alone.
