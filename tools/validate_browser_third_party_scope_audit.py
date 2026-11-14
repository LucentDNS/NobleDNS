#!/usr/bin/env python3
"""Validate pinned browser third-party rules against the evidence queue and source snapshot."""
from __future__ import annotations
import argparse
import csv
from pathlib import Path

SOURCE_COMMIT = "69965fa59a5d5a44531768780850d3e788fa93e1"
REQUIRED_WARNING = "cannot preserve request-party context"

def validate(queue_path: Path, audit_path: Path, source_path: Path) -> list[str]:
    errors: list[str] = []
    with queue_path.open(encoding="utf-8", newline="") as f:
        queue = list(csv.DictReader(f))
    with audit_path.open(encoding="utf-8", newline="") as f:
        audit = list(csv.DictReader(f))
    source_lines = source_path.read_text(encoding="utf-8").splitlines()
    queue_hosts = {row["rule"].removeprefix("||").removesuffix("^") for row in queue}
    seen: set[str] = set()
    required = {"hostname", "browser_rule", "source_line", "source_commit", "scope", "dns_implication"}
    if not audit or not required.issubset(audit[0]):
        return ["audit is empty or missing required columns"]
    for number, row in enumerate(audit, start=2):
        host = row.get("hostname", "").strip()
        if not host or host in seen:
            errors.append(f"row {number}: blank or duplicate hostname {host!r}")
        seen.add(host)
        rule = row.get("browser_rule", "").strip()
        if host not in queue_hosts:
            errors.append(f"row {number}: hostname is absent from the 69-host evidence queue: {host}")
        if rule != f"||{host}$third-party":
            errors.append(f"row {number}: not the exact third-party browser rule for {host}")
        if row.get("source_commit", "").strip() != SOURCE_COMMIT:
            errors.append(f"row {number}: source commit is not pinned for {host}")
        if row.get("scope", "").strip() != "third-party":
            errors.append(f"row {number}: unexpected scope for {host}")
        try:
            source_line = int(row.get("source_line", ""))
            if source_line < 1:
                raise ValueError
            actual = source_lines[source_line - 1].strip()
            if actual != rule:
                errors.append(f"row {number}: source line {source_line} does not contain the exact rule for {host}")
        except (ValueError, IndexError):
            errors.append(f"row {number}: invalid or out-of-range source line for {host}")
        if REQUIRED_WARNING not in row.get("dns_implication", ""):
            errors.append(f"row {number}: DNS scope-loss warning missing for {host}")
    if len(audit) != len(seen):
        errors.append("audit row count differs from unique hostname count")
    return errors

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    errors = validate(args.queue, args.audit, args.source)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    with args.audit.open(encoding="utf-8", newline="") as f:
        count = sum(1 for _ in csv.DictReader(f))
    print(f"Validated {count} exact third-party browser rules and source-line matches against the pinned snapshot.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
