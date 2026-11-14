#!/usr/bin/env python3
"""Validate evidence-queue uniqueness and source attribution against the generated audit."""
from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter
from pathlib import Path

FIELDS = [
    "rule", "source", "source_line", "priority", "observed_context",
    "evidence_type", "evidence_url", "interpretation", "decision_status",
]
AUDIT_FIELDS = [
    "rule", "source", "source_line_numbers", "essential_match_count",
    "essential_matches", "review_status", "interpretation",
]
RULE_RE = re.compile(r"^\|\|[a-z0-9.-]+$")
URL_RE = re.compile(r"https://\S+")
PRIORITIES = {"high", "medium", "low"}
FLOATING_GITHUB_REF_RE = re.compile(r"https?://(?:github\.com/.+/blob|raw\.githubusercontent\.com/.+)/(?:master|main)/")


def read_rows(path: Path, fields: list[str]) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != fields:
            raise ValueError(f"{path}: columns must exactly match {','.join(fields)}")
        return list(reader)


def validate(audit_path: Path, queue_path: Path) -> tuple[Counter[str], list[str]]:
    errors: list[str] = []
    audit_rows = read_rows(audit_path, AUDIT_FIELDS)
    queue_rows = read_rows(queue_path, FIELDS)
    audit_by_rule: dict[str, dict[str, str]] = {}
    for line_no, row in enumerate(audit_rows, 2):
        rule = row["rule"].strip().lower()
        if rule in audit_by_rule:
            errors.append(f"{audit_path}:{line_no}: duplicate audit rule {rule}")
        audit_by_rule[rule] = row

    seen: set[str] = set()
    counts: Counter[str] = Counter()
    for line_no, row in enumerate(queue_rows, 2):
        rule = row["rule"].strip().lower()
        priority = row["priority"].strip().lower()
        counts[priority] += 1
        if not RULE_RE.fullmatch(rule):
            errors.append(f"{queue_path}:{line_no}: invalid bare-anchor rule {rule!r}")
        if rule in seen:
            errors.append(f"{queue_path}:{line_no}: duplicate queue rule {rule}")
        seen.add(rule)
        audit = audit_by_rule.get(rule)
        if audit is None:
            errors.append(f"{queue_path}:{line_no}: rule absent from current audit: {rule}")
        else:
            if row["source"].strip() != audit["source"]:
                errors.append(f"{queue_path}:{line_no}: source mismatch for {rule}")
            source_lines = set(filter(None, audit["source_line_numbers"].split(";")))
            if row["source_line"].strip() not in source_lines:
                errors.append(f"{queue_path}:{line_no}: source line mismatch for {rule}")
        if priority not in PRIORITIES:
            errors.append(f"{queue_path}:{line_no}: invalid priority {priority!r}")
        for field in ("observed_context", "evidence_type", "interpretation", "decision_status"):
            if not row[field].strip():
                errors.append(f"{queue_path}:{line_no}: {field} is required for {rule}")
        urls = URL_RE.findall(row["evidence_url"])
        if not urls or any(not url.startswith("https://") for url in urls):
            errors.append(f"{queue_path}:{line_no}: at least one HTTPS evidence URL is required for {rule}")
        if FLOATING_GITHUB_REF_RE.search(row["evidence_url"]):
            errors.append(f"{queue_path}:{line_no}: GitHub evidence file URLs must use immutable commit refs for {rule}")
        if not row["decision_status"].strip().startswith("unresolved_"):
            errors.append(f"{queue_path}:{line_no}: queue entries must remain unresolved: {rule}")
    return counts, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=Path("dist/bare-anchor-audit.csv"))
    parser.add_argument(
        "--queue",
        type=Path,
        default=Path("benchmark/discovery/bare-anchor-app-risk-triage.csv"),
    )
    args = parser.parse_args()
    try:
        counts, errors = validate(args.audit, args.queue)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("Bare-anchor evidence queue validation failed:", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Validated {sum(counts.values())} unique unresolved evidence rows; priorities: {dict(sorted(counts.items()))}")
    print("LIMITATION: source attribution and queue integrity only; no hostname is certified safe or app-compatible.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
