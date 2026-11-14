#!/usr/bin/env python3
"""Audit active DNS exceptions that overlap compiled blocking rules.

This is a static rule-semantics audit. It identifies scope interactions; it
does not decide whether an exception is justified or whether a client honors
the expected precedence.
"""
from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$")


def valid_host(host: str) -> bool:
    return len(host) <= 253 and all(
        len(label) <= 63 for label in host.split(".")
    ) and bool(HOST_RE.fullmatch(host))


def parse_block(line: str) -> tuple[str, bool] | None:
    if not line.startswith("||"):
        return None
    pattern = line[2:]
    caret = pattern.endswith("^")
    host = pattern[:-1] if caret else pattern
    if not valid_host(host):
        return None
    return host.lower(), caret


def parse_exception(line: str) -> str | None:
    if not line.startswith("@@||") or not line.endswith("^"):
        return None
    host = line[4:-1]
    return host.lower() if valid_host(host) else None


def overlap_relation(exception_host: str, block_host: str, block_caret: bool) -> str | None:
    """Return a conservative, explainable overlap relation or None."""
    e, b = exception_host.lower(), block_host.lower()
    if block_caret:
        if e == b:
            return "same_domain"
        if e.endswith("." + b):
            return "exception_below_block"
        if b.endswith("." + e):
            return "block_below_exception"
        return None

    # Bare || anchors have no end boundary. The following cases establish
    # a potential intersection with the exception's domain/subdomain tree.
    if e == b:
        return "bare_anchor_same_domain"
    if e.startswith(b) or ("." + b) in e or b.endswith("." + e):
        return "bare_anchor_potential_overlap"
    return None


def audit(rules_path: Path) -> list[dict[str, str]]:
    blocks: list[tuple[str, bool, str]] = []
    exceptions: list[tuple[str, str]] = []
    for raw in rules_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "#")):
            continue
        if line.startswith("@@"):
            host = parse_exception(line)
            if host:
                exceptions.append((line, host))
        else:
            parsed = parse_block(line)
            if parsed:
                blocks.append((parsed[0], parsed[1], line))

    rows: list[dict[str, str]] = []
    for exception_rule, exception_host in exceptions:
        matches = []
        for block_host, block_caret, block_rule in blocks:
            relation = overlap_relation(exception_host, block_host, block_caret)
            if relation:
                matches.append((block_rule, relation))

        # A parent exception can neutralize a more specific block subtree;
        # prioritize it for human review. Child exceptions are narrower but
        # still need a rationale and client-side verification.
        if any(relation == "block_below_exception" for _, relation in matches):
            priority = "high"
        elif matches:
            priority = "medium"
        else:
            priority = "none"

        rows.append({
            "exception_rule": exception_rule,
            "exception_host": exception_host,
            "overlap_count": str(len(matches)),
            "overlapping_block_rules": " ; ".join(rule for rule, _ in matches),
            "overlap_relations": " ; ".join(f"{rule} [{relation}]" for rule, relation in matches),
            "review_priority": priority,
            "interpretation": (
                "Static overlap only; exception precedence may allow matching names. "
                "Review evidence, scope and real-client behavior before changing the rule."
                if matches else
                "No overlap found among the supported blocking rules in this snapshot; "
                "this does not establish that the exception is necessary."
            ),
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.rules.is_file():
        parser.error(f"rules file does not exist: {args.rules}")
    rows = audit(args.rules)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "exception_rule", "exception_host", "overlap_count",
        "overlapping_block_rules", "overlap_relations", "review_priority",
        "interpretation",
    ]
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    total = sum(int(row["overlap_count"]) > 0 for row in rows)
    print(f"Audited {len(rows)} active exceptions; {total} overlap.")
    print("LIMITATION: static scope analysis only; not evidence that an exception is justified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
