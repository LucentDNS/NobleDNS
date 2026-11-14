# Benchmark discovery data (not ground truth)

This directory contains **discovery-only inputs** for building an independently reviewed NobleDNS benchmark corpus. Nothing here is pre-classified as safe, malicious, advertising, tracking, or suitable for blocking.

## Seed dataset

- File: [http-archive-third-party-domains-2026-06.csv](http-archive-third-party-domains-2026-06.csv)
- Source: [webtracking-data, immutable commit 282d07ce9d4656478815ad7e83869f4bc2262cb5](https://github.com/Aelmgren/webtracking-data/tree/282d07ce9d4656478815ad7e83869f4bc2262cb5/crawl/2026-06)
- Original file: [third-party-domains.csv](https://raw.githubusercontent.com/Aelmgren/webtracking-data/282d07ce9d4656478815ad7e83869f4bc2262cb5/crawl/2026-06/third-party-domains.csv)
- Dataset description: [webtracking-data README](https://github.com/Aelmgren/webtracking-data/blob/282d07ce9d4656478815ad7e83869f4bc2262cb5/README.md)
- License: **CC BY 4.0** for `crawl/` datasets. Attribution: “Data: webtracking.org (https://webtracking.org), CC BY 4.0”.
- Snapshot: HTTP Archive 2026-06 crawl aggregates. The upstream project reports 15.7 million root pages in this crawl.
- Included rows: 100 third-party request domains, copied without changing the original six columns.

## Correct interpretation

The source records how often third-party request domains appeared in the crawl and how often their requests set cookies. This is useful for prioritizing review, but it is **not a blocklist and not a ground-truth label set**.

In particular:

- A domain appearing frequently does not mean it should be blocked.
- A high cookie-setting share does not by itself prove advertising or tracking.
- A domain with a low cookie-setting share may still be an important functional dependency.
- Large shared infrastructure, CDNs, identity, payment, analytics and platform domains require hostname- and function-level investigation.
- The crawl is a web measurement dataset; it does not represent mainland-China mobile applications, all regions, or all users.

## How to promote a candidate into the scored corpus

1. Record the exact hostname and the specific observed function/request context.
2. Gather evidence independent of NobleDNS, AdGuard DNS Filter and HaGeZi.
3. Assign a category only when the evidence supports it; otherwise leave it unresolved.
4. Record evidence URL, concise evidence summary, confidence, review date and expiry where applicable.
5. Obtain a primary review and a genuinely distinct independent review.
6. Add only fully reviewed records to `tests/fixtures/reviewed-benchmark-corpus.csv` using the exact schema in `tests/fixtures/reviewed-benchmark-corpus.template.csv`.
7. Keep the discovery file intact; do not silently turn its rows into block/allow labels.

The offline scorer must continue to refuse an empty or invalid reviewed corpus. Discovery candidates must never be counted in TP/FP/FN/TN or used to publish an efficacy percentage.

## Provenance and attribution

The source dataset is distributed under CC BY 4.0. NobleDNS includes this discovery snapshot with attribution; see the upstream [license statement](https://github.com/Aelmgren/webtracking-data/blob/282d07ce9d4656478815ad7e83869f4bc2262cb5/LICENSE.md). The upstream data is derived from the public [HTTP Archive](https://httparchive.org/) crawl. NobleDNS is not affiliated with webtracking.org, HTTP Archive, or any domain owner listed in the dataset.
