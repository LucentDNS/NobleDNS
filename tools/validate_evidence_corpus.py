#!/usr/bin/env python3
"""Validate NobleDNS's evidence-backed regression corpus using stdlib only."""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import update as builder  # Reuse NobleDNS's production hostname validator.

CORPUS_VERSION = 1
CLASSIFICATIONS = {
    "confirmed_ad",
    "confirmed_tracker",
    "unwanted_telemetry",
    "threat",
    "essential_service",
    "unresolved",
}
EVIDENCE_TYPES = {
    "controlled_traffic_capture",
    "vendor_documentation",
    "independent_research",
    "threat_intelligence",
    "upstream_rule",
    "user_report",
    "synthetic_test",
}
POLICIES = {"blocked", "allowed", "observe_only"}
CONFIDENCE = {"high", "medium", "low"}
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_FIELDS = {
    "hostname",
    "classification",
    "evidence_type",
    "evidence_reference",
    "observed_at_utc",
    "reviewed_at_utc",
    "review_due_utc",
    "confidence",
    "service",
    "affected_function",
    "source_rule_refs",
    "source_snapshot_sha256",
    "expected_policy",
    "review_notes",
}
OPTIONAL_FIELDS = {"expires_at_utc"}
TOP_LEVEL_FIELDS = {"schema_version", "records"}


def _parse_utc(value: Any, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        errors.append(f"{field} must be an ISO-8601 UTC timestamp ending in Z")
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        errors.append(f"{field} is not a valid ISO-8601 timestamp")
        return None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        errors.append(f"{field} must use UTC")
        return None
    return parsed


def validate_record(record: Any, index: int, now: datetime) -> list[str]:
    prefix = f"records[{index}]"
    errors: list[str] = []
    if not isinstance(record, dict):
        return [f"{prefix} must be an object"]

    keys = set(record)
    missing = REQUIRED_FIELDS - keys
    unknown = keys - REQUIRED_FIELDS - OPTIONAL_FIELDS
    if missing:
        errors.append(f"{prefix} missing fields: {', '.join(sorted(missing))}")
    if unknown:
        errors.append(f"{prefix} has unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        return errors

    hostname = record["hostname"]
    if not isinstance(hostname, str) or hostname != hostname.lower():
        errors.append(f"{prefix}.hostname must be a lowercase FQDN")
    else:
        valid, reason = builder.valid_domain(hostname)
        if not valid:
            errors.append(f"{prefix}.hostname is invalid: {reason}")

    if not isinstance(record["classification"], str) or record["classification"] not in CLASSIFICATIONS:
        errors.append(f"{prefix}.classification is not an allowed classification")
    if not isinstance(record["evidence_type"], str) or record["evidence_type"] not in EVIDENCE_TYPES:
        errors.append(f"{prefix}.evidence_type is not an allowed evidence type")
    if not isinstance(record["expected_policy"], str) or record["expected_policy"] not in POLICIES:
        errors.append(f"{prefix}.expected_policy is not an allowed policy")
    if not isinstance(record["confidence"], str) or record["confidence"] not in CONFIDENCE:
        errors.append(f"{prefix}.confidence is not an allowed confidence")
    for field in ("evidence_reference", "service", "affected_function", "review_notes"):
        value = record[field]
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{prefix}.{field} must be a non-empty string")

    refs = record["source_rule_refs"]
    if not isinstance(refs, list) or any(not isinstance(x, str) or not x.strip() for x in refs):
        errors.append(f"{prefix}.source_rule_refs must be an array of non-empty strings")
    elif len(refs) != len(set(refs)):
        errors.append(f"{prefix}.source_rule_refs contains duplicates")

    hashes = record["source_snapshot_sha256"]
    if not isinstance(hashes, list) or any(
        not isinstance(x, str) or not HASH_RE.fullmatch(x) for x in hashes
    ):
        errors.append(f"{prefix}.source_snapshot_sha256 must be an array of lowercase SHA-256 hashes")
    elif len(hashes) != len(set(hashes)):
        errors.append(f"{prefix}.source_snapshot_sha256 contains duplicates")
    if isinstance(refs, list) and refs and isinstance(hashes, list) and not hashes:
        errors.append(f"{prefix} has source rule references but no source snapshot hash")

    observed = _parse_utc(record["observed_at_utc"], f"{prefix}.observed_at_utc", errors)
    reviewed = _parse_utc(record["reviewed_at_utc"], f"{prefix}.reviewed_at_utc", errors)
    due = _parse_utc(record["review_due_utc"], f"{prefix}.review_due_utc", errors)
    expires = None
    if "expires_at_utc" in record:
        expires = _parse_utc(record["expires_at_utc"], f"{prefix}.expires_at_utc", errors)
    if observed and reviewed and reviewed < observed:
        errors.append(f"{prefix}.reviewed_at_utc must not precede observed_at_utc")
    if reviewed and due and due < reviewed:
        errors.append(f"{prefix}.review_due_utc must not precede reviewed_at_utc")
    if due and due < now:
        errors.append(f"{prefix} review is overdue; revalidate before using this record")
    if expires and expires <= now:
        errors.append(f"{prefix} evidence has expired; revalidate before using this record")

    classification = record["classification"] if isinstance(record["classification"], str) else ""
    evidence_type = record["evidence_type"] if isinstance(record["evidence_type"], str) else ""
    policy = record["expected_policy"] if isinstance(record["expected_policy"], str) else ""
    confidence = record["confidence"] if isinstance(record["confidence"], str) else ""

    if classification == "unresolved" and policy != "observe_only":
        errors.append(f"{prefix}: unresolved records must use observe_only policy")
    if classification == "confirmed_ad":
        if policy != "blocked":
            errors.append(f"{prefix}: confirmed_ad records must expect blocked policy")
        if evidence_type in {"upstream_rule", "user_report", "synthetic_test"} or confidence != "high":
            errors.append(f"{prefix}: confirmed_ad requires high-confidence non-upstream evidence")
    if classification == "threat":
        if policy != "blocked":
            errors.append(f"{prefix}: threat records must expect blocked policy")
        if evidence_type != "threat_intelligence" or confidence != "high":
            errors.append(f"{prefix}: threat requires high-confidence threat_intelligence evidence")
        if expires is None:
            errors.append(f"{prefix}: threat records require expires_at_utc")
    if classification == "essential_service" and policy != "allowed":
        errors.append(f"{prefix}: essential_service records must expect allowed policy")
    if classification in {"confirmed_tracker", "unwanted_telemetry"} and policy == "allowed":
        errors.append(f"{prefix}: privacy-risk records cannot be ground-truth allowed services")
    if evidence_type == "upstream_rule" and classification != "unresolved":
        errors.append(f"{prefix}: upstream_rule evidence alone cannot establish a confirmed classification")

    return errors


def validate_corpus(data: Any, now: datetime | None = None) -> list[str]:
    now = now or datetime.now(timezone.utc)
    if not isinstance(data, dict):
        return ["corpus root must be an object"]
    errors: list[str] = []
    unknown = set(data) - TOP_LEVEL_FIELDS
    missing = TOP_LEVEL_FIELDS - set(data)
    if missing:
        errors.append(f"corpus missing fields: {', '.join(sorted(missing))}")
    if unknown:
        errors.append(f"corpus has unknown fields: {', '.join(sorted(unknown))}")
    if data.get("schema_version") != CORPUS_VERSION:
        errors.append(f"schema_version must equal {CORPUS_VERSION}")
    records = data.get("records")
    if not isinstance(records, list):
        errors.append("records must be an array")
        return errors
    seen: set[str] = set()
    for index, record in enumerate(records):
        errors.extend(validate_record(record, index, now))
        if isinstance(record, dict) and isinstance(record.get("hostname"), str):
            hostname = record["hostname"]
            if hostname in seen:
                errors.append(f"records[{index}].hostname duplicates {hostname}")
            seen.add(hostname)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", nargs="?", default="tests/fixtures/evidence-corpus.json")
    args = parser.parse_args()
    path = Path(args.corpus)
    if not path.is_absolute():
        path = ROOT / path
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read valid JSON corpus: {exc}", file=sys.stderr)
        return 2
    errors = validate_corpus(data)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"OK: evidence corpus valid ({len(data['records'])} records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
