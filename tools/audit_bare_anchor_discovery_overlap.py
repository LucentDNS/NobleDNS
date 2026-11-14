#!/usr/bin/env python3
"""Diagnostic overlap scan of bare-anchor rules against HTTP Archive discovery hosts.

The discovery seed is not ground truth. Any match is a review lead; zero matches
is not proof of general compatibility.
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

from audit_bare_anchor_safety import matches_bare_anchor


AUDIT_FIELDS = [
    "rule", "source", "source_line_numbers", "essential_match_count",
    "essential_matches", "review_status", "interpretation",
]
DISCOVERY_FIELD = "request_domain"
OUTPUT_FIELDS = [
    "rule", "source", "source_line_numbers", "discovery_match_count",
    "discovery_matches", "review_status", "interpretation",
]


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def audit(audit_path: Path, discovery_path: Path) -> list[dict[str, str]]:
    with audit_path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != AUDIT_FIELDS:
            raise ValueError(f"Audit columns must exactly match: {','.join(AUDIT_FIELDS)}")
        rules = list(reader)

    with discovery_path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or DISCOVERY_FIELD not in reader.fieldnames:
            raise ValueError(f"Discovery CSV must contain {DISCOVERY_FIELD!r}")
        hosts = sorted({
            (row.get(DISCOVERY_FIELD) or "").strip().lower().rstrip(".")
            for row in reader
            if (row.get(DISCOVERY_FIELD) or "").strip()
        })

    output = []
    for row in rules:
        rule = row["rule"].strip().lower()
        if not rule.startswith("||"):
            continue
        pattern = rule[2:]
        hits = sorted(host for host in hosts if matches_bare_anchor(host, pattern))
        output.append({
            "rule": rule,
            "source": row["source"],
            "source_line_numbers": row["source_line_numbers"],
            "discovery_match_count": str(len(hits)),
            "discovery_matches": ";".join(hits),
            "review_status": "discovery_overlap_review_required" if hits else "no_match_in_discovery_seed",
            "interpretation": (
                "Matched one or more HTTP Archive discovery candidates; investigate the exact host and request context."
                if hits else
                "No match in the current HTTP Archive discovery seed; this is not proof of general safety or effectiveness."
            ),
        })
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--discovery", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    for path in (args.audit, args.discovery):
        if not path.is_file():
            parser.error(f"required input does not exist: {path}")
    rows = audit(args.audit, args.discovery)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    matches = [row for row in rows if int(row["discovery_match_count"]) > 0]
    print(f"Audited {len(rows)} bare-anchor rules against the HTTP Archive discovery seed.")
    print(f"Discovery-domain overlaps requiring review: {len(matches)}")
    print("LIMITATION: discovery candidates are not ground truth; zero matches is not a compatibility clearance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
