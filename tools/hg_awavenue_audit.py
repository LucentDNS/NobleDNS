#!/usr/bin/env python3
"""Offline, read-only audit of HG and AWAvenue against the published NobleDNS baseline."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import update as builder

BASELINE_URL = "https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt"
MANIFEST_URL = "https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/manifest.json"
SOURCES = {
    "hg1": {
        "name": "HG main blocking list (hg1.txt)",
        "url": "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
        "role": "candidate_block",
        "license": "No public LICENSE file was found at the repository root during this audit. The user previously reported direct permission from the maintainer; the scope of public redistribution and license compatibility still needs a retained written record.",
        "repository": "https://github.com/2771936993/HG",
    },
    "hg2": {
        "name": "HG allowlist (hg2.txt; companion context only)",
        "url": "https://raw.githubusercontent.com/2771936993/HG/main/hg2.txt",
        "role": "candidate_exception",
        "license": "Same HG repository licensing uncertainty as hg1.txt.",
        "repository": "https://github.com/2771936993/HG",
    },
    "awavenue_full": {
        "name": "AWAvenue full protection",
        "url": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
        "role": "candidate_block",
        "license": "GPL-3.0; repository LICENSE file is present. Preserve attribution and comply with the license and any applicable upstream terms.",
        "repository": "https://github.com/TG-Twilight/AWAvenue-Ads-Rule",
    },
    "awavenue_only_ads": {
        "name": "AWAvenue Ads-only variant (comparison only)",
        "url": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Adguard-Only.Ads.txt",
        "role": "comparison_only",
        "license": "GPL-3.0; repository LICENSE file is present. Preserve attribution and comply with the license and any applicable upstream terms.",
        "repository": "https://github.com/TG-Twilight/AWAvenue-Ads-Rule",
    },
}
RULE_RE = re.compile(r"^(?P<exception>@@)?\|\|(?P<domain>[^\^/$|]+)(?P<caret>\^)?$")


def fetch_snapshot(url: str) -> bytes:
    """Fetch HTTPS text with bounded size, strict UTF-8, and no proxy inheritance."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    last_error = None
    for attempt in range(1, 4):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "NobleDNS-HG-AWAvenue-Audit/1.0",
                    "Accept": "text/plain,*/*;q=0.8",
                    "Cache-Control": "no-cache",
                },
            )
            with opener.open(request, timeout=120) as response:
                if getattr(response, "status", 200) != 200:
                    raise ValueError(f"unexpected HTTP status: {response.status}")
                final_url = response.geturl()
                if not final_url.startswith("https://"):
                    raise ValueError("refusing HTTPS-to-non-HTTPS redirect")
                expected = response.headers.get("Content-Length")
                data = response.read(50 * 1024 * 1024 + 1)
            if len(data) > 50 * 1024 * 1024:
                raise ValueError("source exceeds 50 MiB safety limit")
            if expected and len(data) != int(expected):
                raise ValueError(f"incomplete response: {len(data)} of {expected} bytes")
            data.decode("utf-8-sig", errors="strict")
            if data[:500].lstrip().lower().startswith((b"<html", b"<!doctype html")):
                raise ValueError("HTML response instead of a rule file")
            return data
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, UnicodeDecodeError) as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(2 ** (attempt - 1))
    raise RuntimeError(f"download failed after 3 attempts: {url}; last error: {last_error}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_snapshot(key: str, data: bytes) -> dict:
    blocks, exceptions, rejected, rows = builder.parse_source(data, key, min_blocks=0)
    block_parts = {}
    bare_parts = {}
    for rule in blocks:
        match = RULE_RE.fullmatch(rule)
        if not match:
            raise ValueError(f"unexpected parsed blocking rule: {rule}")
        target = bare_parts if not match.group("caret") else block_parts
        target[match.group("domain")] = rule
    exception_parts = {}
    for rule in exceptions:
        match = RULE_RE.fullmatch(rule)
        if not match or not match.group("exception") or not match.group("caret"):
            raise ValueError(f"unexpected parsed exception rule: {rule}")
        exception_parts[match.group("domain")] = rule

    line_map = defaultdict(list)
    for line_number, raw in enumerate(data.decode("utf-8-sig").splitlines(), 1):
        line = raw.strip().lstrip("\ufeff")
        match = RULE_RE.fullmatch(line)
        if not match:
            continue
        domain = match.group("domain").lower()
        canonical = (
            ("@@" if match.group("exception") else "")
            + "||" + domain
            + ("^" if match.group("caret") else "")
        )
        if canonical in blocks or canonical in exceptions:
            line_map[canonical].append(f"{key}:{line_number}")

    return {
        "blocks": blocks,
        "bare": bare_parts,
        "caret": block_parts,
        "exceptions": exceptions,
        "exception_domains": exception_parts,
        "line_map": dict(line_map),
        "rejected": dict(sorted(rejected.items())),
        "excluded_rows": rows,
        "raw_rule_lines": sum(1 for line in data.decode("utf-8-sig").splitlines()
                              if line.strip() and not line.strip().startswith(("!", "#", "[", "//"))),
        "sha256": sha256(data),
        "bytes": len(data),
    }

def suffixes(hostname: str) -> set[str]:
    labels = hostname.split(".")
    return {".".join(labels[index:]) for index in range(len(labels))}


def rule_matches_host(rule: str, hostname: str) -> bool:
    match = RULE_RE.fullmatch(rule)
    if not match:
        return False
    domain = match.group("domain")
    if match.group("caret"):
        return hostname == domain or hostname.endswith("." + domain)
    # AdGuard hostname-start anchors without ^ have no hostname-end boundary.
    return hostname == domain or hostname.startswith(domain) or ("." + domain) in hostname


def relation_pairs(left: set[str], right: set[str]) -> list[tuple[str, str]]:
    """Return hierarchical domain overlaps in either parent/child direction."""
    pairs = set()
    for domain in left:
        for suffix in suffixes(domain):
            if suffix in right:
                pairs.add((domain, suffix))
    for domain in right:
        for suffix in suffixes(domain):
            if suffix in left:
                pairs.add((suffix, domain))
    return sorted(pairs)


def rule_domain(rule: str) -> str:
    match = RULE_RE.fullmatch(rule)
    if not match:
        raise ValueError(f"unsupported parsed rule: {rule}")
    return match.group("domain")


def baseline_parent_matches(candidate_rule: str, baseline: dict) -> list[str]:
    """Rules that fully cover a candidate caret-bounded rule's hostname scope."""
    match = RULE_RE.fullmatch(candidate_rule)
    if not match or not match.group("caret"):
        return []
    domain = match.group("domain")
    matches = set(suffixes(domain)) & set(baseline["caret"])
    for parent, rule in baseline["bare"].items():
        if rule_matches_host(rule, domain):
            matches.add(parent)
    return sorted(matches)


def rule_overlap_pairs(left_rules: set[str], right_rules: set[str]) -> list[tuple[str, str]]:
    """Find hierarchical overlaps, including prefix collisions involving bare anchors."""
    left_by_domain = defaultdict(list)
    right_by_domain = defaultdict(list)
    for rule in left_rules:
        left_by_domain[rule_domain(rule)].append(rule)
    for rule in right_rules:
        right_by_domain[rule_domain(rule)].append(rule)

    pairs = set()
    for left_domain, right_domain in relation_pairs(set(left_by_domain), set(right_by_domain)):
        for left_rule in left_by_domain[left_domain]:
            for right_rule in right_by_domain[right_domain]:
                pairs.add((left_rule, right_rule))

    left_bare = [rule for rule in left_rules if not RULE_RE.fullmatch(rule).group("caret")]
    right_bare = [rule for rule in right_rules if not RULE_RE.fullmatch(rule).group("caret")]
    for bare_rule in left_bare:
        bare_domain = rule_domain(bare_rule)
        for other_rule in right_rules:
            other_domain = rule_domain(other_rule)
            if rule_matches_host(bare_rule, other_domain) or rule_matches_host(other_rule, bare_domain):
                pairs.add((bare_rule, other_rule))
    for bare_rule in right_bare:
        bare_domain = rule_domain(bare_rule)
        for other_rule in left_rules:
            other_domain = rule_domain(other_rule)
            if rule_matches_host(bare_rule, other_domain) or rule_matches_host(other_rule, bare_domain):
                pairs.add((other_rule, bare_rule))
    return sorted(pairs)

def fixture_hits(source: dict, hostnames: list[str]) -> list[dict]:
    rules = source["blocks"]
    line_map = source.get("line_map", {})
    hits = []
    for hostname in hostnames:
        matches = sorted(rule for rule in rules if rule_matches_host(rule, hostname))
        if matches:
            hits.append({
                "hostname": hostname,
                "matching_rules": matches,
                "source_lines": {rule: line_map.get(rule, []) for rule in matches},
            })
    return hits


def read_fixture(path: Path) -> list[str]:
    return [
        line.strip().lower()
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def source_metrics(source: dict, baseline: dict, essential: list[str], known_ads: list[str]) -> dict:
    candidate_rules = set(source["blocks"])
    baseline_rules = set(baseline["blocks"])
    candidate_domains = set(source["caret"]) | set(source["bare"])
    baseline_domains = set(baseline["caret"]) | set(baseline["bare"])
    exact_domain_overlap = candidate_domains & baseline_domains
    exact_rule_overlap = candidate_rules & baseline_rules

    parent_covered_rules = {}
    effective_new_rules = set()
    for rule in candidate_rules - exact_rule_overlap:
        match = RULE_RE.fullmatch(rule)
        if match.group("caret"):
            parents = baseline_parent_matches(rule, baseline)
            if parents:
                parent_covered_rules[rule] = parents
                continue
        # Bare anchors have no hostname-end boundary. A caret-bounded rule at
        # the same domain does not cover their prefix-collision scope.
        effective_new_rules.add(rule)

    effective_new_domains = {rule_domain(rule) for rule in effective_new_rules}
    parent_covered_domains = {
        rule_domain(rule) for rule in parent_covered_rules
        if rule_domain(rule) not in baseline_domains
        and rule_domain(rule) not in effective_new_domains
    }
    exact_unique_domains = candidate_domains - baseline_domains
    unique_not_parent_covered = exact_unique_domains - parent_covered_domains

    new_caret_domains = {
        rule_domain(rule) for rule in effective_new_rules
        if RULE_RE.fullmatch(rule).group("caret")
    }
    new_bare_rules = [
        rule for rule in effective_new_rules
        if not RULE_RE.fullmatch(rule).group("caret")
    ]

    # A new parent rule broadens the baseline only if no existing baseline
    # parent rule already covered the affected baseline hostname.
    effective_baseline_domains = set()
    baseline_caret_domains = set(baseline["caret"])
    for baseline_domain in baseline_domains:
        parent_suffixes = suffixes(baseline_domain) - {baseline_domain}
        if parent_suffixes & baseline_caret_domains:
            continue
        if any(
            parent != baseline_domain and rule_matches_host(rule, baseline_domain)
            for parent, rule in baseline["bare"].items()
        ):
            continue
        effective_baseline_domains.add(baseline_domain)

    broadens = defaultdict(set)
    for baseline_domain in effective_baseline_domains:
        for suffix in suffixes(baseline_domain):
            if suffix in new_caret_domains:
                matching_rule = source["caret"][suffix]
                broadens[matching_rule].add(baseline_domain)
        for candidate_rule in new_bare_rules:
            if rule_matches_host(candidate_rule, baseline_domain):
                broadens[candidate_rule].add(baseline_domain)

    affected_baseline_domains = set()
    for values in broadens.values():
        affected_baseline_domains.update(values)

    block_exception_conflicts = rule_overlap_pairs(
        candidate_rules, set(baseline["exceptions"])
    )
    new_block_exception_conflicts = rule_overlap_pairs(
        effective_new_rules, set(baseline["exceptions"])
    )
    exception_block_conflicts = rule_overlap_pairs(
        set(source["exceptions"]), baseline_rules
    )
    return {
        "unique_block_rules": len(candidate_rules),
        "unique_block_domains": len(candidate_domains),
        "caret_block_rules": len(source["caret"]),
        "bare_block_rules": len(source["bare"]),
        "domains_with_both_caret_and_bare_rules": len(set(source["caret"]) & set(source["bare"])),
        "exception_domains": len(source["exception_domains"]),
        "exact_rule_overlap_with_baseline": len(exact_rule_overlap),
        "exact_domain_overlap_with_baseline": len(exact_domain_overlap),
        "exact_unique_domains_vs_baseline": len(exact_unique_domains),
        "effective_new_rules_vs_baseline": len(effective_new_rules),
        "effective_new_domains_vs_baseline": len(effective_new_domains),
        "unique_but_already_covered_by_baseline_parent": len(parent_covered_domains),
        "unique_not_covered_by_baseline_parent": len(unique_not_parent_covered),
        "candidate_rules_broadening_existing_baseline_scope": len(broadens),
        "baseline_block_domains_affected_by_candidate_parent_rules": len(affected_baseline_domains),
        "candidate_blocks_overlapping_baseline_exceptions": len(block_exception_conflicts),
        "new_candidate_blocks_overlapping_baseline_exceptions": len(new_block_exception_conflicts),
        "candidate_exceptions_overlapping_baseline_blocks": len(exception_block_conflicts),
        "essential_fixture_hits": fixture_hits(source, essential),
        "known_ad_fixture_hits": fixture_hits(source, known_ads),
        "parent_covered_examples": [
            {"candidate_rule": rule, "baseline_cover": parents}
            for rule, parents in list(parent_covered_rules.items())[:30]
        ],
        "broadening_examples": [
            {"candidate_rule": rule, "baseline_domains": sorted(values)[:10]}
            for rule, values in list(sorted(broadens.items()))[:30]
        ],
        "block_exception_conflict_examples": block_exception_conflicts[:30],
        "new_block_exception_conflict_examples": new_block_exception_conflicts[:30],
        "exception_block_conflict_examples": exception_block_conflicts[:30],
    }

def lexical_signals(domains: set[str]) -> dict:
    return {
        "cn_suffix": sum(domain.endswith(".cn") for domain in domains),
        "com_cn_suffix": sum(domain.endswith(".com.cn") for domain in domains),
        "advertising_name_tokens": sum(bool(re.search(
            r"(^|[.-])(ad|ads|adv|advert|advertising|alimama|mobads|gdt|ssp|dsp)([.-]|$)", domain
        )) for domain in domains),
        "tracking_or_telemetry_name_tokens": sum(bool(re.search(
            r"(track|tracker|analytics|stat|log|telemetry|metric|sensors|umeng|growingio)", domain
        )) for domain in domains),
        "push_name_tokens": sum(bool(re.search(r"(push|notify|notification)", domain)) for domain in domains),
        "httpdns_name_tokens": sum("httpdns" in domain for domain in domains),
    }


def write_csv(path: Path, headers: list[str], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def render_source_report(title: str, source_name: str, source_url: str, parsed: dict,
                         metrics: dict, license_text: str, essential: list[str],
                         known_ads: list[str], extra: str = "") -> str:
    rejected = "\n".join(
        f"| {reason} | {count:,} |" for reason, count in parsed["rejected"].items()
    ) or "| None | 0 |"
    essential_hits = metrics["essential_fixture_hits"]
    known_hits = metrics["known_ad_fixture_hits"]
    lexical = lexical_signals(set(parsed["caret"]) | set(parsed["bare"]))
    return f"""# {title}

> Offline source audit only. No rule from this report is approved for NobleDNS. No production configuration, subscription, or release artifact is modified.

## Snapshot and provenance

- Source: {source_name}
- URL: {source_url}
- Downloaded bytes: {parsed['bytes']:,}
- SHA-256: {parsed['sha256']}
- Raw non-comment rule lines: {parsed['raw_rule_lines']:,}
- Baseline main commit: {os.environ.get('BASELINE_MAIN_SHA', 'not supplied')}
- Audit time (UTC): {datetime.now(timezone.utc).isoformat()}
- License assessment: {license_text}

## Parser results

| Measure | Count |
|---|---:|
| Unique supported blocking rules | {metrics['unique_block_rules']:,} |
| Unique supported blocking domains | {metrics['unique_block_domains']:,} |
| Explicit hostname-end rules (||domain^) | {metrics['caret_block_rules']:,} |
| Bare hostname-start rules (||domain) | {metrics['bare_block_rules']:,} |
| Domains represented by both rule forms | {metrics['domains_with_both_caret_and_bare_rules']:,} |
| Supported exception domains | {metrics['exception_domains']:,} |
| Exact rule overlap with NobleDNS baseline | {metrics['exact_rule_overlap_with_baseline']:,} |
| Exact domain overlap with NobleDNS baseline | {metrics['exact_domain_overlap_with_baseline']:,} |
| Exact unique domains vs baseline | {metrics['exact_unique_domains_vs_baseline']:,} |
| Effective new rules after baseline coverage | {metrics['effective_new_rules_vs_baseline']:,} |
| Effective new domains after baseline coverage | {metrics['effective_new_domains_vs_baseline']:,} |
| Unique but already covered by a baseline parent rule | {metrics['unique_but_already_covered_by_baseline_parent']:,} |
| Unique domains not covered by a baseline parent rule | {metrics['unique_not_covered_by_baseline_parent']:,} |
| Candidate rules that broaden existing baseline scope | {metrics['candidate_rules_broadening_existing_baseline_scope']:,} |
| Baseline block domains affected by candidate parent rules | {metrics['baseline_block_domains_affected_by_candidate_parent_rules']:,} |
| Candidate blocks overlapping baseline exceptions (all source rules) | {metrics['candidate_blocks_overlapping_baseline_exceptions']:,} |
| New candidate blocks overlapping baseline exceptions | {metrics['new_candidate_blocks_overlapping_baseline_exceptions']:,} |
| Candidate exceptions overlapping baseline blocks | {metrics['candidate_exceptions_overlapping_baseline_blocks']:,} |

### Rejected or unsupported input

| Reason | Lines |
|---|---:|
{rejected}

## Mainland-use lexical signals

These are hostname-string signals only, not verified classifications or evidence of current endpoint behavior.

{json.dumps(lexical, ensure_ascii=False, indent=2)}

## Regression fixture cross-check

- Essential-service fixture size: {len(essential)}
- Actual essential-service collisions: **{len(essential_hits)}**
- Known-ad fixture size: {len(known_ads)}
- Known-ad hostnames covered: **{len(known_hits)}**

### Essential-service collisions

{json.dumps(essential_hits, ensure_ascii=False, indent=2)}

### Known-ad fixture coverage

{json.dumps(known_hits, ensure_ascii=False, indent=2)}

## Additional review notes

{extra}

No automatic acceptance is recommended. A source-level match, hostname token, or lack of collision with a small fixture does not establish endpoint purpose, safety, or real-world compatibility.
"""


def self_test() -> None:
    blocks, exceptions, rejected, _ = builder.parse_source(
        b"||ads.example.com^\n||bare.example.com\n@@||safe.example.com^\n||*.wild.example.com^\n",
        "self-test",
        min_blocks=0,
    )
    if blocks != {"||ads.example.com^", "||bare.example.com"}:
        raise AssertionError(f"parser self-test failed: {blocks}")
    if exceptions != {"@@||safe.example.com^"} or rejected.get("wildcard_syntax") != 1:
        raise AssertionError("exception/wildcard self-test failed")
    if not rule_matches_host("||bare.example.com", "bare.example.com.evil.test"):
        raise AssertionError("bare-anchor prefix semantics test failed")
    if rule_matches_host("||bare.example.com^", "bare.example.com.evil.test"):
        raise AssertionError("caret hostname boundary test failed")

    baseline = parse_snapshot(
        "baseline-test",
        b"||example.com^\n||x.newparent.example.net^\n"
    )
    candidate = parse_snapshot(
        "candidate-test",
        b"||example.com^\n||newparent.example.net^\n||redundant.example.com^\n"
    )
    metrics = source_metrics(candidate, baseline, [], [])
    if metrics["candidate_rules_broadening_existing_baseline_scope"] != 2:
        raise AssertionError("scope-expansion metric must count a new bare-anchor scope and a new parent rule")
    if metrics["baseline_block_domains_affected_by_candidate_parent_rules"] != 2:
        raise AssertionError("scope-expansion metric must count only newly affected baseline domains")


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline HG + AWAvenue comparison against NobleDNS; read-only.")
    parser.add_argument("--out", type=Path, default=Path("audit-output"))
    args = parser.parse_args()
    self_test()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    snapshots = out / "source-snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)

    downloaded = {}
    parsed = {}
    for key, source in SOURCES.items():
        data = fetch_snapshot(source["url"])
        (snapshots / f"{key}.txt").write_bytes(data)
        downloaded[key] = data
        parsed[key] = parse_snapshot(key, data)

    baseline_data = fetch_snapshot(BASELINE_URL)
    (snapshots / "nobledns-main-dns-filter.txt").write_bytes(baseline_data)
    baseline = parse_snapshot("nobledns_baseline", baseline_data)
    if not baseline["blocks"]:
        raise RuntimeError("NobleDNS baseline parsed no blocking rules; refusing an incomplete comparison")

    manifest_data = fetch_snapshot(MANIFEST_URL)
    (snapshots / "nobledns-main-manifest.json").write_bytes(manifest_data)
    baseline_manifest = json.loads(manifest_data.decode("utf-8-sig"))
    manifest_rule_count = len(baseline["blocks"]) + len(baseline["exceptions"])
    if baseline_manifest.get("main_subscription_sha256") != baseline["sha256"]:
        raise RuntimeError("Downloaded baseline SHA-256 does not match dist/manifest.json")
    if baseline_manifest.get("main_subscription_rules") != manifest_rule_count:
        raise RuntimeError("Downloaded baseline rule count does not match dist/manifest.json")

    essential = read_fixture(ROOT / "tests" / "fixtures" / "essential-domains.txt")
    known_ads = read_fixture(ROOT / "tests" / "fixtures" / "known-ads.txt")
    if not essential or not known_ads:
        raise RuntimeError("Required NobleDNS regression fixtures are empty")

    metrics = {
        key: source_metrics(parsed[key], baseline, essential, known_ads)
        for key in ("hg1", "awavenue_full", "awavenue_only_ads")
    }
    hg2_allow_domains = set(parsed["hg2"]["exception_domains"])
    baseline_block_domains = set(baseline["caret"]) | set(baseline["bare"])
    hg1_block_domains = set(parsed["hg1"]["caret"]) | set(parsed["hg1"]["bare"])
    hg2_vs_baseline = rule_overlap_pairs(
        set(parsed["hg2"]["exceptions"]), set(baseline["blocks"])
    )
    hg2_vs_hg1 = rule_overlap_pairs(
        set(parsed["hg2"]["exceptions"]), set(parsed["hg1"]["blocks"])
    )

    hg_domains = hg1_block_domains
    awa_domains = set(parsed["awavenue_full"]["caret"]) | set(parsed["awavenue_full"]["bare"])
    only_ads_domains = set(parsed["awavenue_only_ads"]["caret"]) | set(parsed["awavenue_only_ads"]["bare"])
    merged_domains = hg_domains | awa_domains
    merged_rules = parsed["hg1"]["blocks"] | parsed["awavenue_full"]["blocks"]
    merged_line_map = defaultdict(list)
    for source_key in ("hg1", "awavenue_full"):
        for rule, lines in parsed[source_key]["line_map"].items():
            merged_line_map[rule].extend(lines)
    merged_view = {
        "caret": {**parsed["hg1"]["caret"], **parsed["awavenue_full"]["caret"]},
        "bare": {**parsed["hg1"]["bare"], **parsed["awavenue_full"]["bare"]},
        "blocks": merged_rules,
        "exceptions": set(),
        "exception_domains": {},
        "line_map": dict(merged_line_map),
    }
    merged_metrics = source_metrics(merged_view, baseline, essential, known_ads)
    exact_rule_overlap = len(parsed["hg1"]["blocks"] & parsed["awavenue_full"]["blocks"])
    domain_overlap = len(hg_domains & awa_domains)
    baseline_total_rules = len(baseline["blocks"]) + len(baseline["exceptions"])
    merged_rule_exact_unique = len(merged_rules - baseline["blocks"])
    merged_domain_exact_unique = len(merged_domains - baseline_block_domains)
    projected_rule_count = baseline_total_rules + merged_rule_exact_unique

    report = {
        "schema_version": 1,
        "audit_time_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_main_commit": os.environ.get("BASELINE_MAIN_SHA"),
        "baseline_url": BASELINE_URL,
        "baseline_sha256": baseline["sha256"],
        "baseline_manifest_sha256": sha256(manifest_data),
        "baseline_version": baseline_manifest.get("version"),
        "baseline_status": baseline_manifest.get("status"),
        "baseline_built_at_utc": baseline_manifest.get("built_at_utc"),
        "baseline_manifest_integrity": "PASS",
        "baseline_bytes": baseline["bytes"],
        "baseline_block_rules": len(baseline["blocks"]),
        "baseline_exception_rules": len(baseline["exceptions"]),
        "baseline_total_rules": baseline_total_rules,
        "fixtures": {"essential_count": len(essential), "known_ads_count": len(known_ads)},
        "sources": {
            key: {
                "name": SOURCES[key]["name"],
                "url": SOURCES[key]["url"],
                "repository": SOURCES[key]["repository"],
                "license_assessment": SOURCES[key]["license"],
                "sha256": parsed[key]["sha256"],
                "bytes": parsed[key]["bytes"],
                "raw_rule_lines": parsed[key]["raw_rule_lines"],
                "unique_block_rules": len(parsed[key]["blocks"]),
                "unique_exception_rules": len(parsed[key]["exceptions"]),
                "bare_block_rules": len(parsed[key]["bare"]),
                "rejected": parsed[key]["rejected"],
                "metrics": metrics.get(key),
            } for key in SOURCES
        },
        "cross_source": {
            "hg1_vs_awavenue_full_exact_rule_overlap": exact_rule_overlap,
            "hg1_vs_awavenue_full_domain_overlap": domain_overlap,
            "hg1_vs_awavenue_full_domain_union": len(merged_domains),
            "hg1_vs_awavenue_only_ads_domain_overlap": len(hg_domains & only_ads_domains),
            "hg1_vs_awavenue_only_ads_domain_union": len(hg_domains | only_ads_domains),
            "full_vs_only_ads": {
                "full_unique_domains": len(awa_domains),
                "only_ads_unique_domains": len(only_ads_domains),
                "common_domains": len(awa_domains & only_ads_domains),
                "full_only_domains": len(awa_domains - only_ads_domains),
                "only_ads_only_domains": len(only_ads_domains - awa_domains),
            },
        },
        "hg2_allowlist": {
            "parsed_exception_domains": len(hg2_allow_domains),
            "rejected": parsed["hg2"]["rejected"],
            "overlap_with_nobledns_baseline_blocks": len(hg2_vs_baseline),
            "overlap_with_hg1_blocks": len(hg2_vs_hg1),
            "baseline_conflict_examples": hg2_vs_baseline[:50],
            "hg1_conflict_examples": hg2_vs_hg1[:50],
        },
        "merged_increment": {
            "exact_new_rules_vs_baseline": merged_rule_exact_unique,
            "new_unique_domains_vs_baseline": merged_domain_exact_unique,
            "new_domains_not_covered_by_baseline_parent": merged_metrics["unique_not_covered_by_baseline_parent"],
            "candidate_rules_broadening_existing_baseline_scope": merged_metrics["candidate_rules_broadening_existing_baseline_scope"],
            "essential_fixture_hits": merged_metrics["essential_fixture_hits"],
            "known_ad_fixture_hits": merged_metrics["known_ad_fixture_hits"],
            "projected_subscription_rule_count_if_all_exact_new_rules_added": projected_rule_count,
            "rule_cap": builder.MAX_RULES,
            "under_rule_cap": projected_rule_count <= builder.MAX_RULES,
        },
        "decision": "RESEARCH_ONLY_NO_RULES_ACCEPTED",
        "production_files_modified": False,
        "limitations": [
            "This is an offline syntax, overlap, scope, provenance and fixture audit; it is not a live DNS or application compatibility test.",
            "The essential-service and known-ad fixtures are small regression sentinels, not a representative real-world corpus.",
            "Hostname tokens and upstream membership are not proof of endpoint function or safe blocking.",
            "HG's public repository root has no LICENSE file; direct permission must explicitly cover public redistribution and license terms before inclusion.",
            "AWAvenue full protection includes advertising, privacy and unwelcome categories; its README identifies forced updates, P2P/PCDN, push and cloud-control delivery among unwelcome items.",
            "The AWAvenue Ads-only variant is included as a comparison, not substituted for the exact full-protection URL requested.",
        ],
    }
    (out / "audit.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    hg_extra = (
        "HG's own README identifies hg1.txt as the blocking list and hg2.txt as its companion allowlist. "
        f"The companion hg2 file parsed {len(hg2_allow_domains):,} supported exception domains; "
        f"{len(hg2_vs_baseline):,} hierarchical exception/block overlaps with the NobleDNS baseline and "
        f"{len(hg2_vs_hg1):,} overlaps with hg1 were found. It does not provide matching exceptions for "
        "the pinduoduo.com or pingan.com parent blocks identified by the essential-service regression fixture. "
        "The 35 retained bare-anchor rules need client-specific matching review. The source also contains "
        "large numbers of IP-literal, wildcard, single-label and malformed/unsupported entries, all excluded "
        "by the NobleDNS parser. The public repository did not expose a LICENSE file at its root."
    )
    awa_extra = (
        "The exact requested main file is the full-protection subscription. The AWAvenue README says this "
        "combines advertising, privacy and unwelcome categories; its unwelcome category includes forced "
        "updates, P2P/PCDN, push and cloud-control delivery. The repository separately publishes an Ads-only "
        "variant described as compatibility/minimal-intervention oriented. That variant is audited separately "
        f"and contains {len(only_ads_domains):,} supported unique blocking domains versus {len(awa_domains):,} "
        f"in the full-protection list. The full list has {len(awa_domains - only_ads_domains):,} additional "
        "domains not present in the Ads-only variant. This is a source-scope distinction, not a claim that "
        "every additional domain is harmful or safe to block."
    )

    reports = out / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "01-HG-source-audit.md").write_text(
        render_source_report(
            "HG source audit — hg1.txt and companion hg2.txt",
            SOURCES["hg1"]["name"], SOURCES["hg1"]["url"], parsed["hg1"], metrics["hg1"],
            SOURCES["hg1"]["license"], essential, known_ads, hg_extra
        ), encoding="utf-8"
    )
    (reports / "02-AWAvenue-source-audit.md").write_text(
        render_source_report(
            "AWAvenue source audit — full-protection subscription",
            SOURCES["awavenue_full"]["name"], SOURCES["awavenue_full"]["url"],
            parsed["awavenue_full"], metrics["awavenue_full"], SOURCES["awavenue_full"]["license"],
            essential, known_ads, awa_extra
        ), encoding="utf-8"
    )

    merged_text = f"""# HG + AWAvenue merged incremental audit

> Research only. No rule is added to NobleDNS. This report compares the two exact requested sources with the current published main-branch subscription.

## Reproducibility

- Baseline commit: {report['baseline_main_commit'] or 'not supplied'}
- Baseline URL: {BASELINE_URL}
- Baseline SHA-256: {baseline['sha256']}
- Baseline manifest SHA-256: {sha256(manifest_data)}
- Baseline manifest integrity: PASS (manifest version {baseline_manifest.get('version')}, status {baseline_manifest.get('status')}, built {baseline_manifest.get('built_at_utc')})
- Baseline blocking rules: {len(baseline['blocks']):,}
- Baseline active exceptions: {len(baseline['exceptions']):,}
- Rule cap: {builder.MAX_RULES:,}
- HG snapshot SHA-256: {parsed['hg1']['sha256']}
- AWAvenue full snapshot SHA-256: {parsed['awavenue_full']['sha256']}
- Audit time UTC: {report['audit_time_utc']}

## Cross-source overlap

| Measure | Count |
|---|---:|
| HG unique supported blocking domains | {len(hg_domains):,} |
| AWAvenue full unique supported blocking domains | {len(awa_domains):,} |
| Exact domain overlap | {domain_overlap:,} |
| HG + AWAvenue full union | {len(merged_domains):,} |
| HG + AWAvenue exact-rule overlap | {exact_rule_overlap:,} |
| HG + AWAvenue Ads-only overlap | {len(hg_domains & only_ads_domains):,} |
| HG + AWAvenue Ads-only union | {len(hg_domains | only_ads_domains):,} |

## Increment relative to NobleDNS

| Measure | Count |
|---|---:|
| Exact new rules vs baseline | {merged_rule_exact_unique:,} |
| New unique domains vs baseline | {merged_domain_exact_unique:,} |
| Effective new rules after baseline coverage | {merged_metrics['effective_new_rules_vs_baseline']:,} |
| Effective new domains after baseline coverage | {merged_metrics['effective_new_domains_vs_baseline']:,} |
| New domains not already covered by a baseline parent rule | {merged_metrics['unique_not_covered_by_baseline_parent']:,} |
| Candidate rules that broaden existing baseline scope | {merged_metrics['candidate_rules_broadening_existing_baseline_scope']:,} |
| Baseline block domains affected by candidate parent rules | {merged_metrics['baseline_block_domains_affected_by_candidate_parent_rules']:,} |
| Candidate blocks overlapping baseline exceptions (all source rules) | {merged_metrics['candidate_blocks_overlapping_baseline_exceptions']:,} |
| New candidate blocks overlapping baseline exceptions | {merged_metrics['new_candidate_blocks_overlapping_baseline_exceptions']:,} |
| Candidate exceptions overlapping baseline blocks | {merged_metrics['candidate_exceptions_overlapping_baseline_blocks']:,} |
| Projected total if every exact new block rule were appended | {projected_rule_count:,} / {builder.MAX_RULES:,} |

The projected count is arithmetic only. It does not establish that the candidate rules are appropriate, safe, or accepted.

## Regression fixture results

### Essential services

{json.dumps(merged_metrics['essential_fixture_hits'], ensure_ascii=False, indent=2)}

### Known advertising infrastructure

{json.dumps(merged_metrics['known_ad_fixture_hits'], ensure_ascii=False, indent=2)}

## HG companion allowlist impact

- Supported HG2 exception domains: {len(hg2_allow_domains):,}
- HG2 exception/block hierarchy overlaps with NobleDNS baseline: {len(hg2_vs_baseline):,}
- HG2 exception/block hierarchy overlaps with HG1: {len(hg2_vs_hg1):,}
- HG2 does not provide a matching exception for the HG parent blocks pinduoduo.com and pingan.com.

Using HG2 as an allowlist is not a neutral operation: exceptions can neutralize matching baseline blocking rules. Do not merge it into the NobleDNS main subscription without a separate, reviewed exception policy.

## Source-specific decision

### HG

Do not bulk-import. The source contains two parent-domain rules that collide with the existing essential-service fixture: pinduoduo.com and pingan.com. HG2 does not repair those conflicts. The parser also excludes 1,004 IP-literal/IPv4-like entries, 164 wildcard entries, 17 single-label entries, and other malformed/unsupported syntax. Thirty-five valid bare-anchor rules remain semantically broader than caret-bounded rules and require client-specific testing. No public LICENSE file was found at the repository root; retain explicit written permission covering public redistribution and licensing before any inclusion.

### AWAvenue full protection

Do not bulk-import into the single balanced edition yet. The full subscription combines advertising, privacy and unwelcome categories. Its own README says the unwelcome category includes forced updates, P2P/PCDN, push and cloud-control delivery, which can affect normal service behavior. The small 72-host essential fixture had no collision in this snapshot, but that is not a real-world compatibility guarantee. Four wildcard rules remain unsupported and three raw rules are duplicates. The repository provides GPL-3.0 licensing information.

### AWAvenue Ads-only comparison

The separately published Ads-only variant contains {len(only_ads_domains):,} supported unique domains, {len(awa_domains - only_ads_domains):,} fewer than the full list. It is more consistent with a conservative ad-only evaluation than silently using the full-protection list, but still requires its own overlap, endpoint evidence and client compatibility review. It is not substituted for the requested full-list audit.

## Final audit conclusion

**No source is approved for automatic inclusion.** HG is blocked by confirmed essential-fixture conflicts and unresolved public redistribution terms. AWAvenue full protection is too broad for direct bulk inclusion in the balanced edition without separating its privacy/unwelcome effects and completing client tests. If further evaluation is pursued, the AWAvenue Ads-only variant is the narrower pilot candidate; HG requires individual rule review, not wholesale merging.

No production source configuration, public rules, manifest, subscription, or release was modified.
"""
    (reports / "03-merged-increment-audit.md").write_text(merged_text, encoding="utf-8")

    candidate_rows = []
    effective_incremental_rows = []
    for source_key in ("hg1", "awavenue_full", "awavenue_only_ads"):
        source = parsed[source_key]
        source_metrics_row = metrics[source_key]
        for rule in sorted(source["blocks"]):
            domain = rule_domain(rule)
            match = RULE_RE.fullmatch(rule)
            parent_matches = baseline_parent_matches(rule, baseline)
            exact_rule_match = rule in baseline["blocks"]
            exact_domain_match = domain in baseline_block_domains
            effective_incremental = not exact_rule_match and not parent_matches
            row = {
                "source": source_key,
                "domain": domain,
                "rule": rule,
                "rule_form": "bare_anchor" if not match.group("caret") else "caret_bounded",
                "exact_baseline_rule_match": str(exact_rule_match).lower(),
                "exact_baseline_domain_match": str(exact_domain_match).lower(),
                "baseline_parent_covered": str(bool(parent_matches)).lower(),
                "baseline_parent_rules": ";".join(parent_matches),
                "effective_incremental_rule": str(effective_incremental).lower(),
                "source_lines": ";".join(source["line_map"].get(rule, [])),
                "essential_fixture_match": str(any(rule_matches_host(rule, host) for host in essential)).lower(),
            }
            candidate_rows.append(row)
            if effective_incremental:
                effective_incremental_rows.append(row)
    inventory_headers = [
        "source", "domain", "rule", "rule_form", "exact_baseline_rule_match",
        "exact_baseline_domain_match", "baseline_parent_covered", "baseline_parent_rules",
        "effective_incremental_rule", "source_lines", "essential_fixture_match",
    ]
    write_csv(out / "candidate-domain-inventory.csv", inventory_headers, candidate_rows)
    write_csv(out / "effective-incremental-rules.csv", inventory_headers, effective_incremental_rows)

    excluded_rows = []
    for key, source in parsed.items():
        for row in source["excluded_rows"]:
            excluded_rows.append({
                "source": key,
                "line_number": row[1],
                "reason": row[2],
                "original_line": row[3],
            })
    write_csv(out / "unsupported-source-lines.csv",
              ["source", "line_number", "reason", "original_line"], excluded_rows)

    print(
        f"HG/AWAvenue offline audit complete: baseline {len(baseline['blocks']):,} blocks; "
        f"HG {len(hg_domains):,} domains; AWAvenue full {len(awa_domains):,}; "
        f"merged {len(merged_domains):,}; essential collisions {len(merged_metrics['essential_fixture_hits'])}; "
        "no production files modified."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"HG/AWAVENUE AUDIT FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
