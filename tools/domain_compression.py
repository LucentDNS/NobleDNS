#!/usr/bin/env python3
"""Pinned-PSL-aware, conservative parent/child compression for simple AdGuard rules."""
from __future__ import annotations

import csv
import hashlib
from pathlib import Path

import idna

PSL_COMMIT = "c3a53eed2cc49353c5fb5c30536186795d5c451b"
PSL_SHA256 = "a078bef78fa2c8b5e09c41b44669f7403e0afceca21a3144c2a9f98872b26be6"
PSL_PATH = Path(__file__).resolve().parents[1] / "data" / "public_suffix_list.dat"


def _ascii_domain(value: str) -> str:
    return ".".join(
        idna.encode(label, uts46=True, std3_rules=True).decode("ascii").lower()
        for label in value.split(".")
    )


class PublicSuffixList:
    """PSL matcher implementing exact, wildcard and exception rules, incl. PRIVATE."""

    def __init__(self, path: Path = PSL_PATH):
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != PSL_SHA256:
            raise ValueError(f"Pinned PSL SHA256 mismatch: expected {PSL_SHA256}, got {digest}")
        text = raw.decode("utf-8", errors="strict")
        self.exact: set[str] = set()
        self.wildcard: set[str] = set()
        self.exception: set[str] = set()
        for number, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue
            target = self.exact
            if line.startswith("!"):
                target, line = self.exception, line[1:]
            elif line.startswith("*."):
                target, line = self.wildcard, line[2:]
            try:
                target.add(_ascii_domain(line))
            except (idna.IDNAError, UnicodeError) as exc:
                raise ValueError(f"Invalid rule in pinned PSL at line {number}: {raw_line}") from exc
        if len(self.exact) < 5000 or "com" not in self.exact or "co.uk" not in self.exact:
            raise ValueError("Pinned PSL is incomplete or missing required ICANN sentinels")
        if "blogspot.com" not in self.exact or "ck" not in self.exact or "www.ck" not in self.exception:
            raise ValueError("Pinned PSL is missing PRIVATE/wildcard/exception sentinels")
        self.sha256 = digest

    def public_suffix(self, domain: str) -> str:
        labels = domain.lower().split(".")
        best_length = 1  # PSL prevailing-rule default "*"
        exception_length = 0
        for index in range(len(labels)):
            suffix = ".".join(labels[index:])
            length = len(labels) - index
            if suffix in self.exception and length > exception_length:
                exception_length = length
            if suffix in self.exact and length > best_length:
                best_length = length
            # A "*.suffix" rule consumes one additional label to its left.
            if index > 0 and suffix in self.wildcard:
                best_length = max(best_length, length + 1)
        if exception_length:
            best_length = exception_length - 1
        return ".".join(labels[-best_length:])

    def is_public_suffix(self, domain: str) -> bool:
        return self.public_suffix(domain) == domain.lower()


def compress_simple_domain_rules(
    rules: set[str],
    source_rules: dict[str, set[str]],
    psl: PublicSuffixList,
) -> tuple[set[str], list[dict[str, str]]]:
    """Remove only ||child.parent^ when an existing non-PSL ||parent^ covers it.

    Bare anchors, wildcards, modifiers, exceptions and every other syntax form
    are deliberately outside this transformation.
    """
    simple: dict[str, str] = {}
    for rule in rules:
        if rule.startswith("||") and rule.endswith("^") and "$" not in rule and "*" not in rule:
            hostname = rule[2:-1]
            if hostname and "." in hostname:
                simple[hostname] = rule

    removed: dict[str, str] = {}
    for hostname in sorted(simple, key=lambda value: (value.count("."), value)):
        labels = hostname.split(".")
        # nearest existing ancestor wins; never compress against a public suffix
        for index in range(1, len(labels) - 1):
            parent = ".".join(labels[index:])
            if parent not in simple:
                continue
            if psl.is_public_suffix(parent):
                continue
            removed[hostname] = parent
            break

    kept = set(rules)
    rows: list[dict[str, str]] = []
    for child, parent in sorted(removed.items()):
        child_rule, parent_rule = simple[child], simple[parent]
        child_sources = sorted(key for key, values in source_rules.items() if child_rule in values)
        parent_sources = sorted(key for key, values in source_rules.items() if parent_rule in values)
        kept.discard(child_rule)
        rows.append({
            "removed_rule": child_rule,
            "covered_by": parent_rule,
            "child_sources": ";".join(child_sources),
            "parent_sources": ";".join(parent_sources),
        })
    return kept, rows


def write_compression_audit(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["removed_rule", "covered_by", "child_sources", "parent_sources"],
        )
        writer.writeheader()
        writer.writerows(rows)
