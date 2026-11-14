#!/usr/bin/env python3
"""Score a reviewed hostname corpus against supported AdGuard DNS hostname rules.

This is an offline rule-semantics evaluator, not a live DNS/client test.
Supported forms: ||domain^, ||domain, hostname wildcards, $important,
and simple exception forms with optional $important.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import csv
import json
import re
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

RULE_RE = re.compile(r"^(?P<exception>@@)?\|\|(?P<domain>[^\^/$|]+)(?P<caret>\^)?(?:\$(?P<modifier>important))?$")
WILDCARD_LABEL_RE = re.compile(r"^[a-z0-9*](?:[a-z0-9*-]{0,61}[a-z0-9*])?$", re.I)
CATEGORIES = {"ad", "tracking", "telemetry", "threat", "essential", "legitimate"}
FIELDS = [
    "hostname", "category", "expected", "evidence_ref", "evidence_summary",
    "confidence", "reviewed_on", "expires_on", "independent", "reviewer", "independent_reviewer",
]
IPV4_LIKE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def valid_hostname(value: str) -> bool:
    if not value or not value.isascii() or len(value) > 253 or "." not in value or value.endswith("."):
        return False
    if IPV4_LIKE_RE.fullmatch(value):
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    labels = value.split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?", label)
        for label in labels
    )


def valid_wildcard_pattern(value: str) -> bool:
    """Match the compiler's conservative hostname-wildcard acceptance subset."""
    if not value or value.endswith(".") or len(value) > 253 or "*" not in value:
        return False
    labels = value.split(".")
    if len(labels) < 2 or "*" in labels[-1]:
        return False
    if sum("*" not in label for label in labels) < 2:
        return False
    if any(not WILDCARD_LABEL_RE.fullmatch(label) for label in labels):
        return False
    return valid_hostname(value.replace("*", "x"))


def file_identity(path: Path) -> dict[str, str | int]:
    """Return immutable identity metadata for a benchmark input artifact."""
    data = path.read_bytes()
    return {
        "path": str(path),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def load_corpus(path: Path, today: date) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    errors: list[str] = []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != FIELDS:
            raise ValueError(f"Corpus columns must exactly match: {','.join(FIELDS)}")
        seen: set[str] = set()
        for line_no, raw in enumerate(reader, 2):
            row = {key: (raw.get(key) or "").strip() for key in FIELDS}
            host = row["hostname"].lower()
            if host.endswith("."):
                host = host[:-1]
            if not host:
                continue
            problems = []
            if not valid_hostname(host):
                problems.append("invalid hostname")
            if host in seen:
                problems.append("duplicate hostname")
            seen.add(host)
            if row["category"] not in CATEGORIES:
                problems.append("invalid category")
            expected_policy = {
                "ad": "block", "tracking": "block", "telemetry": "block", "threat": "block",
                "essential": "allow", "legitimate": "allow",
            }.get(row["category"])
            if row["expected"] not in {"block", "allow"}:
                problems.append("expected must be block or allow")
            elif expected_policy and row["expected"] != expected_policy:
                problems.append(f"category {row['category']} requires expected={expected_policy}")
            if not row["evidence_ref"] or not row["evidence_summary"]:
                problems.append("missing evidence reference/summary")
            if row["confidence"] != "high":
                problems.append("only high-confidence rows are scoreable")
            reviewed = None
            try:
                reviewed = date.fromisoformat(row["reviewed_on"])
                if reviewed > today:
                    problems.append("review date is in the future")
            except ValueError:
                problems.append("reviewed_on must be YYYY-MM-DD")
            if row["category"] == "threat" and not row["expires_on"]:
                problems.append("threat evidence requires an expiry date")
            if row["expires_on"]:
                try:
                    expires = date.fromisoformat(row["expires_on"])
                    if expires < today:
                        problems.append("evidence expired")
                    if reviewed is not None and expires < reviewed:
                        problems.append("expiry date precedes review date")
                except ValueError:
                    problems.append("expires_on must be YYYY-MM-DD or blank")
            if row["independent"].lower() != "true":
                problems.append("evidence must be marked independent=true")
            if not row["reviewer"]:
                problems.append("missing reviewer")
            if not row["independent_reviewer"]:
                problems.append("missing independent reviewer")
            elif row["independent_reviewer"] == row["reviewer"]:
                problems.append("independent reviewer must differ from primary reviewer")
            if problems:
                errors.append(f"line {line_no} ({host}): " + "; ".join(problems))
            else:
                row["hostname"] = host
                rows.append(row)
    return rows, errors


def load_rules(path: Path) -> tuple[set[str], set[str], list[str]]:
    blocks: set[str] = set()
    exceptions: set[str] = set()
    unsupported: list[str] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("!", "#")):
            continue
        match = RULE_RE.fullmatch(line)
        if not match:
            unsupported.append(f"line {line_no}: {line}")
            continue
        domain = match.group("domain").lower()
        if domain.endswith("."):
            unsupported.append(f"line {line_no}: invalid hostname in {line}")
            continue
        valid = valid_wildcard_pattern(domain) if "*" in domain else valid_hostname(domain)
        if not valid:
            unsupported.append(f"line {line_no}: invalid hostname or wildcard in {line}")
            continue
        is_exception = bool(match.group("exception"))
        has_caret = bool(match.group("caret"))
        important = match.group("modifier") == "important"
        if important and not has_caret:
            unsupported.append(f"line {line_no}: $important requires a hostname-end separator in {line}")
            continue
        if is_exception and not has_caret:
            unsupported.append(f"line {line_no}: unsupported exception {line}")
            continue
        canonical = "||" + domain + ("^" if has_caret else "") + ("$important" if important else "")
        if is_exception:
            exceptions.add("@@" + canonical)
        else:
            blocks.add(canonical)
    return blocks, exceptions, unsupported

def rule_matches(hostname: str, rule: str) -> bool:
    """Apply AdGuard hostname anchors, wildcard masks and end separators."""
    match = RULE_RE.fullmatch(rule.removeprefix("@@"))
    if not match:
        return False
    domain = match.group("domain")
    has_caret = bool(match.group("caret"))
    # || anchors at the hostname start or at a subdomain label boundary.
    # A bare anchor deliberately does not require the hostname to end here.
    expression = r"(?:^|\.)" + re.escape(domain).replace(r"\*", ".*")
    expression += "$" if has_caret else ""
    return re.search(expression, hostname, flags=re.IGNORECASE) is not None

def matches(hostname: str, rules: set[str]) -> list[str]:
    return sorted(rule for rule in rules if rule_matches(hostname, rule))


def decide(hostname: str, blocks: set[str], exceptions: set[str]) -> tuple[str, list[str]]:
    matched_blocks = matches(hostname, blocks)
    matched_exceptions = matches(hostname, exceptions)
    important_blocks = [rule for rule in matched_blocks if rule.endswith("$important")]
    important_exceptions = [rule for rule in matched_exceptions if rule.endswith("$important")]
    # AdGuard priority: important exception > important block > basic exception > basic block.
    if important_exceptions:
        return "allow", important_exceptions
    if important_blocks:
        return "block", important_blocks
    if matched_exceptions:
        return "allow", matched_exceptions
    if matched_blocks:
        return "block", matched_blocks
    return "allow", []

def score(rows: list[dict], blocks: set[str], exceptions: set[str]) -> dict:
    categories: dict[str, dict[str, int]] = defaultdict(lambda: {
        "tp": 0, "fp": 0, "tn": 0, "fn": 0, "total": 0
    })
    outcomes = []
    for row in rows:
        actual, matched = decide(row["hostname"], blocks, exceptions)
        expected = row["expected"]
        item = categories[row["category"]]
        item["total"] += 1
        if expected == "block" and actual == "block":
            item["tp"] += 1
            outcome = "TP"
        elif expected == "block":
            item["fn"] += 1
            outcome = "FN"
        elif actual == "block":
            item["fp"] += 1
            outcome = "FP"
        else:
            item["tn"] += 1
            outcome = "TN"
        outcomes.append({
            "hostname": row["hostname"], "category": row["category"], "expected": expected,
            "actual": actual, "outcome": outcome, "matched_rules": matched,
            "evidence_ref": row["evidence_ref"],
        })
    overall = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "total": len(rows)}
    summary = {}
    for category, values in sorted(categories.items()):
        for key in ("tp", "fp", "tn", "fn"):
            overall[key] += values[key]
        policy = "block" if category in {"ad", "tracking", "telemetry", "threat"} else "allow"
        tp, fp, tn, fn = (values[k] for k in ("tp", "fp", "tn", "fn"))
        summary[category] = {
            **values,
            "expected_policy": policy,
            "block_recall": round(tp / (tp + fn), 6) if policy == "block" and tp + fn else None,
            "false_block_rate": round(fp / (fp + tn), 6) if policy == "allow" and fp + tn else None,
        }
    tp, fp, tn, fn = (overall[k] for k in ("tp", "fp", "tn", "fn"))
    overall["precision"] = round(tp / (tp + fp), 6) if tp + fp else None
    overall["recall"] = round(tp / (tp + fn), 6) if tp + fn else None
    overall["specificity"] = round(tn / (tn + fp), 6) if tn + fp else None
    return {"scored_records": len(rows), "overall": overall, "by_category": summary, "outcomes": outcomes}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--today", default=date.today().isoformat(), help="Override date for reproducible tests (YYYY-MM-DD)")
    args = parser.parse_args()
    try:
        today = date.fromisoformat(args.today)
        rows, corpus_errors = load_corpus(args.corpus, today)
        blocks, exceptions, unsupported = load_rules(args.rules)
        if corpus_errors:
            print("Corpus validation failed:", file=sys.stderr)
            print("\n".join(corpus_errors), file=sys.stderr)
            return 2
        if unsupported:
            print(f"Rules file contains {len(unsupported)} unsupported lines; refusing partial score.", file=sys.stderr)
            print("\n".join(unsupported[:20]), file=sys.stderr)
            return 2
        if not rows:
            print("No independently reviewed, current, high-confidence corpus records; refusing to produce a score.", file=sys.stderr)
            return 2
        result = score(rows, blocks, exceptions)
        result["artifacts"] = {
            "rules": file_identity(args.rules),
            "corpus": file_identity(args.corpus),
            "scorer": file_identity(Path(__file__).resolve()),
        }
        result["evaluation_date"] = today.isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Scored {len(rows)} reviewed records; report: {args.output}")
        for category, values in result["by_category"].items():
            print(f"{category}: TP={values['tp']} FP={values['fp']} TN={values['tn']} FN={values['fn']} block_recall={values['block_recall']} false_block_rate={values['false_block_rate']}")
        print("LIMITATION: offline hostname-rule simulation only; not a live DNS/client or application test.")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
