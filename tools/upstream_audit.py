#!/usr/bin/env python3
"""NobleDNS upstream candidate audit. Never modifies public subscriptions."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import update as builder  # Reuse the production parser; do not create a second syntax definition.

SOURCES = {
    "adguard_dns": {"name": "AdGuard DNS Filter", "role": "baseline", "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "license": "GPL-3.0"},
    "hagezi_normal": {"name": "HaGeZi Multi NORMAL", "role": "baseline", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt", "license": "GPL-3.0"},
    "oisd_big": {"name": "OISD Big", "role": "candidate", "url": "https://big.oisd.nl/", "license": "GPL-3.0"},
    "anti_ad": {"name": "anti-AD (AdGuard format)", "role": "candidate", "url": "https://anti-ad.net/adguard.txt", "license": "MIT"},
    "adrules_dns": {"name": "AdRules DNS", "role": "candidate", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt", "license": "0BSD"},
}
RULE_DOMAIN_RE = re.compile(r"^(?:@@)?\|\|([^\^/$|]+)(?:\^)?$")

def rule_domain(rule: str) -> str:
    match = RULE_DOMAIN_RE.fullmatch(rule)
    if not match:
        raise ValueError(f"Production parser returned an unexpected rule form: {rule}")
    return match.group(1)

def is_covered(domain: str, rules: set[str]) -> bool:
    labels = domain.split(".")
    return any(".".join(labels[i:]) in rules for i in range(len(labels)))

def fetch(url: str) -> bytes:
    return builder.fetch(url, None)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="audit-output")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    snapshots = out / "source-snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)
    parsed, metadata, failures = {}, {}, {}

    for key, source in SOURCES.items():
        try:
            raw = fetch(source["url"])
            (snapshots / f"{key}.txt").write_bytes(raw)
            blocks, exceptions, rejected, _rows = builder.parse_source(raw, key, min_blocks=0)
            block_domains = {rule_domain(rule) for rule in blocks}
            exception_domains = {rule_domain(rule) for rule in exceptions}
            parsed[key] = {"blocks": block_domains, "exceptions": exception_domains}
            metadata[key] = {
                **source,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "snapshot": f"source-snapshots/{key}.txt",
                "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
                "blocking_rules": len(blocks),
                "blocking_domains": len(block_domains),
                "exception_rules": len(exceptions),
                "exception_domains": len(exception_domains),
                "unsupported_lines_by_reason": dict(sorted(rejected.items())),
            }
            print(f"OK {key}: {len(blocks)} blocking rules, {len(exceptions)} exceptions")
        except Exception as exc:
            failures[key] = f"{type(exc).__name__}: {exc}"
            print(f"ERROR {key}: {failures[key]}", file=sys.stderr)

    baseline_keys = [k for k in ("adguard_dns", "hagezi_normal") if k in parsed]
    if len(baseline_keys) != 2:
        raise RuntimeError("Both current NobleDNS baseline sources must download and parse; refusing incomplete comparison.")
    baseline = set().union(*(parsed[k]["blocks"] for k in baseline_keys))
    baseline_exceptions = set().union(*(parsed[k]["exceptions"] for k in baseline_keys))

    manifest_path = ROOT / "dist" / "manifest.json"
    published_manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}
    published_sources = published_manifest.get("sources", {})
    baseline_fingerprint_comparison = {}
    for key in baseline_keys:
        published_sha = published_sources.get(key, {}).get("sha256")
        current_sha = metadata[key]["sha256"]
        baseline_fingerprint_comparison[key] = {
            "published_manifest_sha256": published_sha,
            "downloaded_sha256": current_sha,
            "matches_published_manifest": published_sha == current_sha if published_sha else None,
        }

    comparisons, unique_rows = {}, []
    candidate_keys = [k for k, source in SOURCES.items() if source["role"] == "candidate" and k in parsed]
    candidate_unique_sets = {}
    for key in candidate_keys:
        blocks = parsed[key]["blocks"]
        exact_overlap, unique_exact = blocks & baseline, blocks - baseline
        covered_by_parent = {d for d in unique_exact if is_covered(d, baseline)}
        candidate_unique_sets[key] = unique_exact
        comparisons[key] = {
            "candidate_blocking_domains": len(blocks),
            "exact_overlap_with_current_baseline": len(exact_overlap),
            "exact_overlap_percent": round(len(exact_overlap) / len(blocks) * 100, 3) if blocks else 0,
            "exact_unique_vs_current_baseline": len(unique_exact),
            "unique_but_already_covered_by_baseline_parent_rule": len(covered_by_parent),
            "unique_not_covered_by_baseline_parent_rule": len(unique_exact - covered_by_parent),
            "candidate_exceptions": len(parsed[key]["exceptions"]),
            "candidate_exceptions_intersecting_baseline_blocks": len(parsed[key]["exceptions"] & baseline),
            "candidate_blocks_intersecting_baseline_exceptions": len(blocks & baseline_exceptions),
            "unique_cn_domains": sum(d.endswith(".cn") for d in unique_exact),
            "unique_com_cn_domains": sum(d.endswith(".com.cn") for d in unique_exact),
        }
        for domain in sorted(unique_exact):
            unique_rows.append({
                "source": key, "domain": domain,
                "already_covered_by_baseline_parent": str(domain in covered_by_parent).lower(),
                "ends_in_cn": str(domain.endswith(".cn")).lower(),
            })

    pairwise_candidate_overlap = {}
    for index, left in enumerate(candidate_keys):
        for right in candidate_keys[index + 1:]:
            pairwise_candidate_overlap[f"{left}__{right}"] = {
                "overlap_between_candidate_unique_sets": len(candidate_unique_sets[left] & candidate_unique_sets[right])
            }
    union_unique = set().union(*candidate_unique_sets.values()) if candidate_unique_sets else set()
    union_parent_covered = {d for d in union_unique if is_covered(d, baseline)}

    exception_rows = []
    for key in parsed:
        for domain in sorted(parsed[key]["exceptions"]):
            baseline_exact = domain in baseline
            baseline_child_blocks = sorted(d for d in baseline if is_covered(d, {domain}) and d != domain)
            baseline_parent_blocks = sorted(d for d in baseline if is_covered(domain, {d}) and d != domain)
            exception_rows.append({
                "source": key, "exception_domain": domain,
                "exact_baseline_block_conflict": str(baseline_exact).lower(),
                "baseline_blocked_subdomains_neutralized": ";".join(baseline_child_blocks),
                "baseline_parent_blocks": ";".join(baseline_parent_blocks),
            })
    with (out / "candidate-unique-rules.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["source", "domain", "already_covered_by_baseline_parent", "ends_in_cn"])
        writer.writeheader()
        writer.writerows(unique_rows)
    with (out / "exception-conflicts.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["source", "exception_domain", "exact_baseline_block_conflict", "baseline_blocked_subdomains_neutralized", "baseline_parent_blocks"])
        writer.writeheader()
        writer.writerows(exception_rows)

    report = {
        "project": "NobleDNS",
        "audit_type": "candidate source comparison; not a merge or acceptance decision",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "published_baseline_version": published_manifest.get("version"),
        "published_baseline_main_sha256": published_manifest.get("main_subscription_sha256"),
        "baseline_sources": baseline_keys,
        "baseline_unique_blocking_domains": len(baseline),
        "baseline_exception_domains": len(baseline_exceptions),
        "baseline_fingerprint_comparison": baseline_fingerprint_comparison,
        "sources": metadata,
        "candidate_comparisons": comparisons,
        "pairwise_candidate_overlap": pairwise_candidate_overlap,
        "candidate_union_exact_unique_domains": len(union_unique),
        "candidate_union_unique_not_covered_by_baseline_parent": len(union_unique - union_parent_covered),
        "candidate_union_unique_already_covered_by_baseline_parent": len(union_parent_covered),
        "candidate_union_plus_baseline_exact_domain_total": len(baseline | union_unique),
        "candidate_union_incremental_by_source_order": {},
        "download_or_parse_failures": failures,
        "limitations": [
            "The production NobleDNS parser is reused so syntax acceptance matches the current builder; parser exclusions are not silently converted.",
            "This is a domain-set comparison, not a semantic effectiveness or false-positive measurement.",
            "Exact unique domains may already be covered by a broader baseline parent-domain rule; these are counted separately.",
            "Exception precedence and client-specific matching behavior require separate compatibility tests.",
            "A domain appearing in an upstream list is not by itself proof that it is safe or appropriate to block.",
            "Moving source URLs are snapshots of this run; hashes and included source-snapshot files identify the exact downloaded bytes.",
            "The .cn suffix count is a rough geographic signal only; it is not a complete mainland-specific classification.",
        ],
    }
    seen = set()
    for key in candidate_keys:
        report["candidate_union_incremental_by_source_order"][key] = len(candidate_unique_sets[key] - seen)
        seen.update(candidate_unique_sets[key])
    (out / "audit.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# NobleDNS upstream source audit", "",
        f"Generated (UTC): {report['generated_at_utc']}",
        f"Published baseline version: {report.get('published_baseline_version')}",
        "",
        "> Research artifact only. No source is automatically approved and no public subscription is modified.",
        "",
        f"Live baseline snapshot: {len(baseline):,} unique blocking domains; {len(baseline_exceptions):,} exception domains.",
        "",
        "## Baseline snapshot vs published manifest", "",
        "| Source | Published SHA-256 | Downloaded SHA-256 | Match |",
        "|---|---|---|---|",
    ]
    for key, values in baseline_fingerprint_comparison.items():
        lines.append(f"| {SOURCES[key]['name']} | {values['published_manifest_sha256']} | {values['downloaded_sha256']} | {values['matches_published_manifest']} |")
    lines += [
        "", "## Candidate comparison", "",
        "| Candidate | Parsed blocks | Exact overlap | Exact unique | Unique not covered by baseline parent rule | .cn unique | Exceptions |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for key, values in comparisons.items():
        lines.append(
            f"| {SOURCES[key]['name']} | {values['candidate_blocking_domains']:,} | "
            f"{values['exact_overlap_with_current_baseline']:,} ({values['exact_overlap_percent']}%) | "
            f"{values['exact_unique_vs_current_baseline']:,} | "
            f"{values['unique_not_covered_by_baseline_parent_rule']:,} | "
            f"{values['unique_cn_domains']:,} | {values['candidate_exceptions']:,} |"
        )
    lines += [
        "", f"Candidate unique-domain union vs baseline: {len(union_unique):,}",
        f"Of those, not already covered by a baseline parent rule: {len(union_unique - union_parent_covered):,}",
        "", "## Candidate-to-candidate overlap", "",
        "| Pair | Overlap between each source's baseline-unique set |", "|---|---:|",
    ]
    for pair, values in pairwise_candidate_overlap.items():
        lines.append(f"| {pair} | {values['overlap_between_candidate_unique_sets']:,} |")
    lines += [
        "", "## Source fingerprints", "",
        "| Source | License declaration | Bytes | SHA-256 | Parsed blocks | Exceptions | Unsupported lines |",
        "|---|---|---:|---|---:|---:|---:|",
    ]
    for values in metadata.values():
        lines.append(
            f"| {values['name']} | {values['license']} | {values['bytes']:,} | {values['sha256']} | "
            f"{values['blocking_rules']:,} | {values['exception_rules']:,} | "
            f"{sum(values['unsupported_lines_by_reason'].values()):,} |"
        )
    lines += ["", "## Exception conflicts", ""]
    lines += [f"- {r['source']}: {r['exception_domain']} (exact baseline conflict: {r['exact_baseline_block_conflict']})" for r in exception_rows] if exception_rows else ["No exception rules found."]
    lines += ["", "## Failures", ""]
    lines += [f"- **{key}:** {value}" for key, value in failures.items()] if failures else ["None."]
    lines += ["", "## Interpretation limits", ""] + [f"- {item}" for item in report["limitations"]]
    (out / "audit-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Reports and source snapshots written to {out}")
    return 1 if failures else 0

if __name__ == "__main__":
    raise SystemExit(main())
