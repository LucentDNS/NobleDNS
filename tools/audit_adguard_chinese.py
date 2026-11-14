#!/usr/bin/env python3
"""Audit AdGuard Chinese filter for DNS-syntax candidates without importing rules."""
from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path

SOURCE_URL = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt"
SOURCE_REPOSITORY = "AdguardTeam/FiltersRegistry"
SOURCE_PATH = "filters/filter_224_Chinese/filter.txt"
RULE_RE = re.compile(r"^\|\|([^/$^|]+)(\^)?$")
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
COSMETIC_RE = re.compile(r"#(?:#|@#|\?#|\$#|%#)")


def valid_hostname(value: str) -> bool:
    if not value or value.endswith(".") or len(value) > 253:
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    labels = value.lower().split(".")
    if len(labels) < 2 or any(not LABEL_RE.fullmatch(x) for x in labels):
        return False
    return True


def classify(line: str) -> str:
    if line.startswith("@@"):
        return "exception"
    if COSMETIC_RE.search(line):
        return "cosmetic_or_element"
    if line.startswith("||") and "$" in line:
        return "domain_with_modifier"
    if line.startswith("||") and "*" in line:
        return "domain_wildcard"
    if line.startswith("||"):
        return "domain_syntax_other"
    if line.startswith("/") or "://" in line or ("/" in line and not line.startswith("//")):
        return "url_or_regex"
    return "other"


def load_current_rules(path: Path) -> tuple[set[str], list[str]]:
    exact: set[str] = set()
    wildcard: list[str] = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "#", "@@")):
            continue
        line = re.sub(r"\$important$", "", line)
        match = RULE_RE.fullmatch(line)
        if not match:
            continue
        domain = match.group(1).lower()
        if "*" in domain:
            wildcard.append(domain)
        elif valid_hostname(domain):
            exact.add(domain)
    return exact, wildcard


def covered_by_current(hostname: str, exact: set[str], wildcard: list[str]) -> bool:
    labels = hostname.split(".")
    suffixes = [".".join(labels[i:]) for i in range(len(labels))]
    if any(suffix in exact for suffix in suffixes):
        return True
    return any(fnmatch.fnmatchcase(suffix, pattern) for suffix in suffixes for pattern in wildcard)


def audit(source: Path, current: Path, csv_path: Path, json_path: Path) -> dict:
    raw = source.read_bytes()
    text = raw.decode("utf-8-sig", errors="strict")
    exact, wildcard = load_current_rules(current)
    counts: Counter[str] = Counter()
    candidate_rows: list[dict[str, str | int]] = []
    seen: set[str] = set()

    for line_no, original in enumerate(text.splitlines(), 1):
        line = original.strip().lstrip("\ufeff")
        if not line or line.startswith(("!", "#", "[")):
            continue
        kind = classify(line)
        counts[kind] += 1
        if kind != "domain_syntax_other":
            continue
        match = RULE_RE.fullmatch(line)
        if not match:
            continue
        hostname = match.group(1).lower()
        if not valid_hostname(hostname):
            counts[kind] -= 1
            counts["invalid_or_non_hostname_domain_syntax"] += 1
            continue
        canonical = f"||{hostname}" + ("^" if match.group(2) else "")
        if canonical in seen:
            counts["duplicate_dns_candidates"] += 1
            continue
        seen.add(canonical)
        covered = covered_by_current(hostname, exact, wildcard)
        counts["dns_syntax_candidates"] += 1
        counts["covered_by_current_suffix_or_wildcard"] += int(covered)
        candidate_rows.append({
            "source_line": line_no,
            "rule": canonical,
            "hostname": hostname,
            "current_coverage": "covered" if covered else "not_covered_by_suffix_or_wildcard",
            "decision": "audit_only_not_approved_for_inclusion",
            "reason": "DNS syntax alone does not establish safe global blocking or independent incremental value",
        })

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(candidate_rows[0]) if candidate_rows else [
            "source_line", "rule", "hostname", "current_coverage", "decision", "reason"
        ])
        writer.writeheader()
        writer.writerows(candidate_rows)

    report = {
        "audit": "AdGuard Chinese DNS-scope audit",
        "status": "AUDIT_ONLY_NO_SOURCE_INTEGRATION",
        "source_url": SOURCE_URL,
        "source_repository": SOURCE_REPOSITORY,
        "source_path": SOURCE_PATH,
        "source_bytes": len(raw),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_lines": len(text.splitlines()),
        "current_subscription_sha256": hashlib.sha256(current.read_bytes()).hexdigest(),
        "classification_counts": dict(sorted(counts.items())),
        "candidate_count": len(candidate_rows),
        "candidate_coverage_count": sum(row["current_coverage"] == "covered" for row in candidate_rows),
        "candidate_not_covered_count": sum(row["current_coverage"] != "covered" for row in candidate_rows),
        "limitations": [
            "A syntactically simple hostname rule is only a DNS-syntax candidate, not proof that global DNS blocking is safe.",
            "The source contains browser-context, platform, first-party and exception semantics that this static audit does not resolve.",
            "Coverage is a conservative suffix/wildcard comparison; it is not a full emulation of every AdGuard client matching edge case.",
            "No candidate is approved or added to the public subscription by this tool.",
        ],
    }
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.source, args.current, args.csv, args.json)
    print(json.dumps({
        "status": report["status"],
        "candidate_count": report["candidate_count"],
        "covered": report["candidate_coverage_count"],
        "not_covered": report["candidate_not_covered_count"],
        "source_sha256": report["source_sha256"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
