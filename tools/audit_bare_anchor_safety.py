#!/usr/bin/env python3
"""Audit bare hostname-start DNS rules against critical-service sentinels.

Bare anchors are supported syntax, but unlike ||domain^ they do not assert
a hostname-end separator. This tool preserves them and checks whether any
currently match the project's critical-service regression sentinels.
"""
from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

DOMAIN_RULE = re.compile(r"^\|\|([A-Za-z0-9.-]+)$")


def read_hosts(path: Path) -> list[str]:
    hosts = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip().lower()
        if not line or line.startswith(("#", "!")):
            continue
        hosts.append(line)
    return hosts


def matches_bare_anchor(hostname: str, pattern: str) -> bool:
    host = hostname.lower().rstrip(".")
    rule_host = pattern.lower().rstrip(".")
    return host.startswith(rule_host) or ("." + rule_host) in host


def source_lines(path: Path) -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for line_no, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if DOMAIN_RULE.fullmatch(line):
            found.setdefault(line.lower(), []).append(line_no)
    return found


def audit(rules_path: Path, source_path: Path, essential_path: Path) -> list[dict[str, str]]:
    rules = []
    for raw in rules_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        match = DOMAIN_RULE.fullmatch(line)
        if match and not line.endswith("^"):
            rules.append((line.lower(), match.group(1).lower()))

    essential = read_hosts(essential_path)
    source_map = source_lines(source_path)
    rows = []
    for rule, host_pattern in sorted(set(rules)):
        hits = sorted(host for host in essential if matches_bare_anchor(host, host_pattern))
        lines = source_map.get(rule, [])
        rows.append({
            "rule": rule,
            "source": "adguard_dns" if lines else "source_not_found",
            "source_line_numbers": ";".join(str(n) for n in lines),
            "essential_match_count": str(len(hits)),
            "essential_matches": ";".join(hits),
            "review_status": "critical_sentinel_conflict" if hits else "manual_hostname_review_required",
            "interpretation": (
                "Potential critical-service false positive: investigate before changing production rules."
                if hits else
                "No match in the current essential-service sentinel set; this is not proof of general safety."
            ),
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--essential", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    for path in (args.rules, args.source, args.essential):
        if not path.is_file():
            parser.error(f"required input does not exist: {path}")
    rows = audit(args.rules, args.source, args.essential)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "rule", "source", "source_line_numbers", "essential_match_count",
        "essential_matches", "review_status", "interpretation",
    ]
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    conflicts = [row for row in rows if int(row["essential_match_count"]) > 0]
    print(f"Audited {len(rows)} bare-anchor rules against {len(read_hosts(args.essential))} essential-service sentinels.")
    print(f"Potential critical-service conflicts: {len(conflicts)}")
    if conflicts:
        for row in conflicts:
            print(f"CONFLICT: {row['rule']} -> {row['essential_matches']}")
        return 2
    print("No bare-anchor rule matched the current essential-service sentinel set.")
    print("LIMITATION: static hostname simulation; not a real client or complete compatibility test.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
