#!/usr/bin/env python3
"""Keep the human bare-anchor review worksheet in exact sync with the build audit.

This validates inventory coverage and metadata integrity only. It does not
classify any hostname as safe, malicious, or compatible.
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter
from pathlib import Path

WORKSHEET_FIELDS = [
    "rule", "source", "source_line", "review_priority", "hostname_cue",
    "classification", "evidence_status", "decision", "reviewer",
    "independent_reviewer", "notes",
]
AUDIT_FIELDS = [
    "rule", "source", "source_line_numbers", "essential_match_count",
    "essential_matches", "review_status", "interpretation",
]
RULE_RE = re.compile(r"^\|\|[a-z0-9.-]+$")
PRIORITIES = {"P0", "P1", "P2"}
CLASSIFICATIONS = {
    "unclassified", "advertising", "tracking", "telemetry", "mixed_use",
    "likely_false_positive", "confirmed_false_positive", "cleared_for_test_scope",
}
EVIDENCE_STATUSES = {
    "not_reviewed", "public_evidence_reviewed", "device_tested",
    "independently_reviewed",
}
DECISIONS = {"pending", "retain", "remove", "narrow", "exception"}


def read_rows(path: Path, fields: list[str]) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != fields:
            raise ValueError(
                f"{path}: columns must exactly match {','.join(fields)}"
            )
        return list(reader)


def validate(audit_path: Path, worksheet_path: Path) -> tuple[Counter[str], list[str]]:
    errors: list[str] = []
    audit_rows = read_rows(audit_path, AUDIT_FIELDS)
    worksheet_rows = read_rows(worksheet_path, WORKSHEET_FIELDS)

    audit_by_rule: dict[str, dict[str, str]] = {}
    for line_no, row in enumerate(audit_rows, 2):
        rule = row["rule"].strip().lower()
        if rule in audit_by_rule:
            errors.append(f"{audit_path}:{line_no}: duplicate audit rule {rule}")
        audit_by_rule[rule] = row
        if row["source"] != "adguard_dns":
            errors.append(f"{audit_path}:{line_no}: unexpected or unattributed source for {rule}")
        if int(row["essential_match_count"]) != 0:
            errors.append(f"{audit_path}:{line_no}: critical sentinel conflict for {rule}")

    counts: Counter[str] = Counter()
    worksheet_by_rule: dict[str, dict[str, str]] = {}
    for line_no, row in enumerate(worksheet_rows, 2):
        rule = row["rule"].strip().lower()
        if not RULE_RE.fullmatch(rule):
            errors.append(f"{worksheet_path}:{line_no}: invalid bare-anchor rule {rule!r}")
        if rule in worksheet_by_rule:
            errors.append(f"{worksheet_path}:{line_no}: duplicate worksheet rule {rule}")
        worksheet_by_rule[rule] = row

        priority = row["review_priority"].strip()
        counts[priority] += 1
        if priority not in PRIORITIES:
            errors.append(f"{worksheet_path}:{line_no}: invalid priority {priority!r}")
        if row["classification"].strip() not in CLASSIFICATIONS:
            errors.append(f"{worksheet_path}:{line_no}: invalid classification for {rule}")
        if row["evidence_status"].strip() not in EVIDENCE_STATUSES:
            errors.append(f"{worksheet_path}:{line_no}: invalid evidence_status for {rule}")
        decision = row["decision"].strip()
        if decision not in DECISIONS:
            errors.append(f"{worksheet_path}:{line_no}: invalid decision for {rule}")
        if decision != "pending":
            if row["classification"].strip() == "unclassified":
                errors.append(f"{worksheet_path}:{line_no}: final decision cannot remain unclassified for {rule}")
            if not row["reviewer"].strip() or not row["independent_reviewer"].strip():
                errors.append(f"{worksheet_path}:{line_no}: final decision requires primary and independent reviewers for {rule}")

        audit_row = audit_by_rule.get(rule)
        if audit_row is None:
            errors.append(f"{worksheet_path}:{line_no}: rule absent from current build audit: {rule}")
            continue
        source_lines = set(filter(None, audit_row["source_line_numbers"].split(";")))
        if row["source"].strip() != audit_row["source"]:
            errors.append(f"{worksheet_path}:{line_no}: source mismatch for {rule}")
        if row["source_line"].strip() not in source_lines:
            errors.append(f"{worksheet_path}:{line_no}: source line mismatch for {rule}")

    missing = set(audit_by_rule) - set(worksheet_by_rule)
    extra = set(worksheet_by_rule) - set(audit_by_rule)
    if missing:
        errors.append(f"worksheet is missing {len(missing)} current audit rules")
    if extra:
        errors.append(f"worksheet contains {len(extra)} rules absent from current audit")
    if len(audit_rows) != len(worksheet_rows):
        errors.append(
            f"row count mismatch: audit={len(audit_rows)} worksheet={len(worksheet_rows)}"
        )
    return counts, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=Path("dist/bare-anchor-audit.csv"))
    parser.add_argument(
        "--worksheet",
        type=Path,
        default=Path("benchmark/review/bare-anchor-review-worksheet.csv"),
    )
    args = parser.parse_args()
    try:
        counts, errors = validate(args.audit, args.worksheet)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("Bare-anchor review worksheet validation failed:", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"Validated {sum(counts.values())} review rows against the current build audit; "
        f"priorities: {dict(sorted(counts.items()))}"
    )
    print(
        "LIMITATION: inventory and metadata integrity only; no hostname is "
        "certified safe or app-compatible by this check."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
