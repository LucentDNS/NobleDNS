#!/usr/bin/env python3
"""NobleDNS upstream candidate audit. Never modifies public subscriptions."""
from __future__ import annotations
import argparse, csv, hashlib, json, re, sys, urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SOURCES = {
    "adguard_dns": {"name": "AdGuard DNS Filter", "role": "baseline", "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"},
    "hagezi_normal": {"name": "HaGeZi Multi NORMAL", "role": "baseline", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt"},
    "oisd_big": {"name": "OISD Big", "role": "candidate", "url": "https://big.oisd.nl/"},
    "anti_ad": {"name": "anti-AD (AdGuard format)", "role": "candidate", "url": "https://anti-ad.net/adguard.txt"},
    "adrules_dns": {"name": "AdRules DNS", "role": "candidate", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt"},
}
ABP_RE = re.compile(r"^(?P<exception>@@)?\|\|(?P<domain>[a-z0-9._-]+)(?P<boundary>\^)?(?P<suffix>\$.*)?$", re.I)
HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::)\s+(?P<domain>\S+)(?:\s+.*)?$", re.I)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
MAX_BYTES = 64 * 1024 * 1024

def normalize_domain(value: str) -> str | None:
    value = value.strip().rstrip(".").lower()
    if not value or any(c in value for c in "*/:"):
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return value if DOMAIN_RE.fullmatch(value) else None

def parse_source(content: str) -> dict:
    blocks, exceptions = set(), set()
    unsupported = Counter()
    raw_noncomment = 0
    for raw in content.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith(("!", "#", "[Adblock")):
            continue
        raw_noncomment += 1
        match = ABP_RE.fullmatch(line)
        if match:
            domain = normalize_domain(match.group("domain"))
            if domain and not match.group("suffix"):
                (exceptions if match.group("exception") else blocks).add(domain)
            else:
                unsupported["invalid_domain_or_modifier"] += 1
            continue
        match = HOSTS_RE.fullmatch(line)
        if match:
            domain = normalize_domain(match.group("domain"))
            if domain:
                blocks.add(domain)
            else:
                unsupported["invalid_hosts_entry"] += 1
            continue
        domain = normalize_domain(line)
        if domain:
            blocks.add(domain)
        elif line.startswith("@@"):
            unsupported["exception_syntax"] += 1
        elif line.startswith("/") or "$" in line or "*" in line:
            unsupported["regex_wildcard_or_modifier"] += 1
        elif line.startswith("|"):
            unsupported["unsupported_anchor_syntax"] += 1
        else:
            unsupported["other_or_non_domain_syntax"] += 1
    return {"blocks": blocks, "exceptions": exceptions, "raw_noncomment_lines": raw_noncomment, "unsupported": dict(sorted(unsupported.items()))}

def is_covered(domain: str, rules: set[str]) -> bool:
    labels = domain.split(".")
    return any(".".join(labels[i:]) in rules for i in range(len(labels)))

def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "NobleDNS-Upstream-Audit/1.0"})
    with urllib.request.urlopen(request, timeout=180) as response:
        final_url = response.geturl()
        if not final_url.startswith("https://"):
            raise ValueError(f"HTTPS downgrade rejected: {url} -> {final_url}")
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"source exceeds {MAX_BYTES} byte safety limit: {url}")
    return data

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="audit-output")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    parsed, metadata, failures = {}, {}, {}
    for key, source in SOURCES.items():
        try:
            raw = fetch(source["url"])
            result = parse_source(raw.decode("utf-8-sig", errors="strict"))
            parsed[key] = result
            metadata[key] = {
                **source, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
                "blocking_domains": len(result["blocks"]), "exception_domains": len(result["exceptions"]),
                "raw_noncomment_lines": result["raw_noncomment_lines"],
                "unsupported_lines_by_reason": result["unsupported"],
            }
            print(f"OK {key}: {len(result['blocks'])} blocks, {len(result['exceptions'])} exceptions")
        except Exception as exc:
            failures[key] = f"{type(exc).__name__}: {exc}"
            print(f"ERROR {key}: {failures[key]}", file=sys.stderr)

    baseline_keys = [k for k in ("adguard_dns", "hagezi_normal") if k in parsed]
    if len(baseline_keys) != 2:
        raise RuntimeError("Both current NobleDNS baseline sources must download and parse; refusing incomplete comparison.")
    baseline = set().union(*(parsed[k]["blocks"] for k in baseline_keys))
    baseline_exceptions = set().union(*(parsed[k]["exceptions"] for k in baseline_keys))
    comparisons, unique_rows = {}, []
    for key, source in SOURCES.items():
        if source["role"] != "candidate" or key not in parsed:
            continue
        blocks = parsed[key]["blocks"]
        exact_overlap, unique_exact = blocks & baseline, blocks - baseline
        covered_by_parent = {d for d in unique_exact if is_covered(d, baseline)}
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
        }
        for domain in sorted(unique_exact):
            unique_rows.append({"source": key, "domain": domain, "already_covered_by_baseline_parent": str(domain in covered_by_parent).lower()})
    with (out / "candidate-unique-rules.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["source", "domain", "already_covered_by_baseline_parent"])
        writer.writeheader()
        writer.writerows(unique_rows)
    report = {
        "project": "NobleDNS", "audit_type": "candidate source comparison; not a merge or acceptance decision",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_sources": baseline_keys, "baseline_unique_blocking_domains": len(baseline),
        "baseline_exception_domains": len(baseline_exceptions), "sources": metadata,
        "candidate_comparisons": comparisons, "download_or_parse_failures": failures,
        "limitations": [
            "This is a syntax-aware domain-set comparison, not a semantic effectiveness or false-positive measurement.",
            "Wildcard, regex, modifier and complex rules are reported as unsupported rather than guessed or rewritten.",
            "Exact unique domains may already be covered by a broader baseline parent-domain rule; these are counted separately.",
            "Exception precedence and client-specific matching behavior require separate compatibility tests.",
            "A domain appearing in an upstream list is not by itself proof that it is safe or appropriate to block.",
            "Moving source URLs are snapshots of this run; hashes identify the exact downloaded bytes.",
        ],
    }
    (out / "audit.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# NobleDNS upstream source audit", "", f"Generated (UTC): {report['generated_at_utc']}", "",
        "> Research artifact only. No source is automatically approved and no public subscription is modified.", "",
        f"Current baseline: {len(baseline):,} unique blocking domains; {len(baseline_exceptions):,} exception domains.", "",
        "## Candidate comparison", "",
        "| Candidate | Parsed blocks | Exact overlap | Exact unique | Unique not covered by baseline parent rule | Exceptions |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for key, values in comparisons.items():
        lines.append(f"| {SOURCES[key]['name']} | {values['candidate_blocking_domains']:,} | {values['exact_overlap_with_current_baseline']:,} ({values['exact_overlap_percent']}%) | {values['exact_unique_vs_current_baseline']:,} | {values['unique_not_covered_by_baseline_parent_rule']:,} | {values['candidate_exceptions']:,} |")
    lines += ["", "## Source fingerprints", "", "| Source | Bytes | SHA-256 | Parsed blocks | Parsed exceptions | Unsupported lines |", "|---|---:|---|---:|---:|---:|"]
    for values in metadata.values():
        lines.append(f"| {values['name']} | {values['bytes']:,} | {values['sha256']} | {values['blocking_domains']:,} | {values['exception_domains']:,} | {sum(values['unsupported_lines_by_reason'].values()):,} |")
    lines += ["", "## Failures", ""]
    lines += [f"- **{key}:** {value}" for key, value in failures.items()] if failures else ["None."]
    lines += ["", "## Interpretation limits", ""] + [f"- {item}" for item in report["limitations"]]
    (out / "audit-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Reports written to {out}")
    return 1 if failures else 0

if __name__ == "__main__":
    raise SystemExit(main())
