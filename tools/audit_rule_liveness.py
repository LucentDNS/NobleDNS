#!/usr/bin/env python3
"""Offline, evidence-gated DNS rule liveness audit. Never removes rules."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import update as builder

SCHEMA_VERSION = 1
RCODES = {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR", "TIMEOUT", "OTHER"}
REQUIRED = {
    "hostname", "observed_at_utc", "resolver", "resolver_operator",
    "resolver_endpoint", "vantage", "qtype", "rcode", "answers",
}
OPTIONAL = {"sinkhole_evidence_reference", "cname_chain", "dnssec_ad", "authority_soa_zones"}
RULE_RE = re.compile(r"^(?:\|\|([^\\^/$|]+)(?:\^)?|@@\|\|([^\\^/$|]+)\^)$")


def parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("observed_at_utc must be an ISO-8601 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("observed_at_utc is not a valid ISO-8601 timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("observed_at_utc must use UTC")
    return parsed


def validate_observations(document: object, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    if not isinstance(document, dict) or set(document) != {"schema_version", "observations"}:
        raise ValueError("observation document must contain exactly schema_version and observations")
    if type(document["schema_version"]) is not int or document["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be integer {SCHEMA_VERSION}")
    rows = document["observations"]
    if not isinstance(rows, list):
        raise ValueError("observations must be an array")

    validated = []
    seen = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not REQUIRED <= set(row) <= REQUIRED | OPTIONAL:
            raise ValueError(f"observation[{index}] has missing or unknown fields")
        hostname = row["hostname"]
        if not isinstance(hostname, str):
            raise ValueError(f"observation[{index}].hostname must be a string")
        valid, reason = builder.valid_domain(hostname)
        if not valid or hostname != hostname.lower():
            raise ValueError(f"observation[{index}] has invalid/non-lowercase hostname: {reason}")
        observed = parse_time(row["observed_at_utc"])
        if observed > now:
            raise ValueError(f"observation[{index}].observed_at_utc is in the future")
        for field in ("resolver", "resolver_operator", "vantage"):
            if not isinstance(row[field], str) or not row[field].strip():
                raise ValueError(f"observation[{index}].{field} must be a non-empty string")
        if not isinstance(row["qtype"], str) or row["qtype"] not in {"A", "AAAA"}:
            raise ValueError(f"observation[{index}].qtype must be A or AAAA")
        if not isinstance(row["rcode"], str) or row["rcode"] not in RCODES:
            raise ValueError(f"observation[{index}].rcode is unsupported")
        answers = row["answers"]
        if not isinstance(answers, list) or any(not isinstance(x, str) or not x for x in answers):
            raise ValueError(f"observation[{index}].answers must be an array of non-empty IP address strings")
        if row["rcode"] != "NOERROR" and answers:
            raise ValueError(f"observation[{index}] cannot have address answers unless rcode is NOERROR")
        for answer in answers:
            try:
                address = ipaddress.ip_address(answer)
            except ValueError as exc:
                raise ValueError(f"observation[{index}] contains a non-IP address answer: {answer}") from exc
            expected_version = 4 if row["qtype"] == "A" else 6
            if address.version != expected_version:
                raise ValueError(f"observation[{index}] answer family does not match qtype {row['qtype']}")
        endpoint = row["resolver_endpoint"]
        if not isinstance(endpoint, str):
            raise ValueError("resolver_endpoint must be a string")
        parsed_endpoint = urlsplit(endpoint)
        if (
            parsed_endpoint.scheme not in {"https", "tls"}
            or not parsed_endpoint.hostname
            or parsed_endpoint.username or parsed_endpoint.password
            or parsed_endpoint.query or parsed_endpoint.fragment
        ):
            raise ValueError("resolver_endpoint must be a safe HTTPS or TLS endpoint")
        if "cname_chain" in row:
            chain = row["cname_chain"]
            if not isinstance(chain, list) or any(not isinstance(x, str) for x in chain):
                raise ValueError("cname_chain must be an array of lowercase FQDNs")
            for target in chain:
                valid, reason = builder.valid_domain(target)
                if not valid or target != target.lower():
                    raise ValueError(f"invalid CNAME target {target}: {reason}")
        if "dnssec_ad" in row and type(row["dnssec_ad"]) is not bool:
            raise ValueError("dnssec_ad must be a boolean")
        if "authority_soa_zones" in row:
            zones = row["authority_soa_zones"]
            if not isinstance(zones, list) or any(not isinstance(x, str) for x in zones):
                raise ValueError("authority_soa_zones must be an array of lowercase FQDNs")
            for zone in zones:
                valid, reason = builder.valid_domain(zone)
                if (
                    not valid or zone != zone.lower()
                    or not (hostname == zone or hostname.endswith("." + zone))
                ):
                    raise ValueError(f"invalid or unrelated SOA authority zone {zone}: {reason}")
        if "sinkhole_evidence_reference" in row:
            reference = row["sinkhole_evidence_reference"]
            if not isinstance(reference, str):
                raise ValueError("sinkhole_evidence_reference must be a string")
            parsed = urlsplit(reference)
            if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
                raise ValueError("sinkhole_evidence_reference must be a safe HTTPS URL")
        identity = (
            hostname, row["resolver"], row["resolver_operator"], row["vantage"],
            row["qtype"], row["observed_at_utc"],
        )
        if identity in seen:
            raise ValueError(f"duplicate observation: {identity}")
        seen.add(identity)
        validated.append({**row, "_time": observed})
    return validated


def load_block_rules(path: Path) -> dict[str, set[str]]:
    domains: dict[str, set[str]] = defaultdict(set)
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "#")):
            continue
        match = RULE_RE.fullmatch(line)
        if not match:
            raise ValueError(f"unsupported rule in liveness input: {line}")
        domain = match.group(1) or match.group(2)
        if match.group(2):
            continue
        valid, reason = builder.valid_domain(domain)
        if not valid:
            raise ValueError(f"invalid rule domain {domain}: {reason}")
        domains[domain].add(line)
    return domains


def load_source_provenance(source_dir: Path | None) -> dict[str, set[str]]:
    if source_dir is None:
        return {}
    manifest_path = source_dir / "sources-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError("source manifest is empty or malformed")
    provenance: dict[str, set[str]] = defaultdict(set)
    for key, metadata in manifest.items():
        filename = metadata.get("filename")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise ValueError(f"unsafe source filename for {key}")
        data = (source_dir / filename).read_bytes()
        import hashlib
        actual = hashlib.sha256(data).hexdigest()
        if actual != metadata.get("sha256"):
            raise ValueError(f"source snapshot hash mismatch for {key}")
        blocks, _exceptions, _rejected, _rows = builder.parse_source(data, key, min_blocks=0)
        for rule in blocks:
            domain_match = re.fullmatch(r"\|\|([^\^/$|]+)\^?", rule)
            if domain_match:
                provenance[domain_match.group(1)].add(key)
    return provenance


def classify(host_rows: list[dict], now: datetime, max_age_days: int) -> tuple[str, dict]:
    cutoff = now - timedelta(days=max_age_days)
    fresh = [row for row in host_rows if cutoff <= row["_time"] <= now]
    if not fresh:
        return "stale_or_missing_observations", {"fresh_observations": 0}

    if any(row.get("sinkhole_evidence_reference") for row in fresh):
        return "sinkhole_observed_manual_review", {"fresh_observations": len(fresh)}

    positive = [
        row for row in fresh
        if row["rcode"] == "NOERROR" and row["answers"]
    ]
    cname_observed = any(row.get("cname_chain") for row in fresh)
    nxdomain = [row for row in fresh if row["rcode"] == "NXDOMAIN"]
    if positive and nxdomain:
        status = "mixed_or_split_horizon"
    elif positive:
        status = "active_dns_answer_observed"
    elif cname_observed:
        status = "cname_chain_observed_manual_review"
    else:
        # Keep only the newest observation for each resolver/operator/vantage/qtype.
        latest = {}
        for row in fresh:
            key = (row["resolver"], row["resolver_operator"], row["vantage"], row["qtype"])
            if key not in latest or row["_time"] > latest[key]["_time"]:
                latest[key] = row
        current = list(latest.values())
        if current and all(row["rcode"] == "NXDOMAIN" for row in current):
            pairs = {(r["resolver"], r["resolver_operator"], r["vantage"]) for r in current}
            operators = {r["resolver_operator"] for r in current}
            vantages = {r["vantage"] for r in current}
            qtypes_by_pair = defaultdict(set)
            for row in current:
                qtypes_by_pair[(row["resolver"], row["resolver_operator"], row["vantage"])].add(row["qtype"])
            complete_pairs = [pair for pair, qtypes in qtypes_by_pair.items() if qtypes == {"A", "AAAA"}]
            dates = [row["_time"] for row in fresh if row["rcode"] == "NXDOMAIN"]
            span = (max(dates) - min(dates)).total_seconds() / 86400
            quorum = (
                len(operators) >= 3
                and len(vantages) >= 2
                and len(complete_pairs) >= 3
                and span >= 7
                and len(complete_pairs) == len(pairs)
            )
            soa_complete = all(row.get("authority_soa_zones") for row in current)
            if quorum and not soa_complete:
                status = "nxdomain_without_authority_soa_manual_review"
            elif quorum:
                status = "stable_nxdomain_candidate_manual_review"
            else:
                status = "insufficient_nxdomain_evidence"
            return status, {
                "fresh_observations": len(fresh),
                "nxdomain_observations_with_soa": sum(
                    1 for row in current if row.get("authority_soa_zones")
                ),
                "resolver_operators": sorted(operators),
                "vantages": sorted(vantages),
                "complete_resolver_vantage_pairs": len(complete_pairs),
                "observation_span_days": round(span, 2),
            }
        if any(row["rcode"] == "NOERROR" and not row["answers"] for row in current):
            status = "nodata_or_no_address"
        elif any(row["rcode"] in {"SERVFAIL", "REFUSED", "FORMERR", "TIMEOUT", "OTHER"} for row in current):
            status = "inconclusive_dns_error"
        elif nxdomain:
            status = "insufficient_nxdomain_evidence"
        else:
            status = "inconclusive"
    return status, {"fresh_observations": len(fresh)}


def audit(rules: dict[str, set[str]], observations: list[dict], provenance: dict[str, set[str]],
          now: datetime, max_age_days: int) -> dict:
    grouped = defaultdict(list)
    for row in observations:
        grouped[row["hostname"]].append(row)
    results = []
    for hostname, rows in sorted(grouped.items()):
        status, metrics = classify(rows, now, max_age_days)
        results.append({
            "hostname": hostname,
            "status": status,
            "in_current_subscription": hostname in rules,
            "matched_rules": sorted(rules.get(hostname, set())),
            "source_keys": sorted(provenance.get(hostname, set())),
            "observation_count": len(rows),
            **metrics,
            "action": (
                "manual_review_only"
                if status in {
                    "stable_nxdomain_candidate_manual_review",
                    "nxdomain_without_authority_soa_manual_review",
                } and hostname in rules
                else "no_change"
            ),
        })
    counts = defaultdict(int)
    for result in results:
        counts[result["status"]] += 1
    return {
        "schema_version": 1,
        "generated_at_utc": now.isoformat().replace("+00:00", "Z"),
        "max_observation_age_days": max_age_days,
        "subscription_blocking_domains": len(rules),
        "observed_hostnames": len(results),
        "observed_hostnames_in_subscription": sum(1 for r in results if r["in_current_subscription"]),
        "status_counts": dict(sorted(counts.items())),
        "stable_nxdomain_candidates": sum(
            1 for r in results if r["status"] == "stable_nxdomain_candidate_manual_review"
        ),
        "automatic_removals": 0,
        "results": results,
    }


def write_outputs(report: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    fields = [
        "hostname", "status", "in_current_subscription", "matched_rules",
        "source_keys", "observation_count", "fresh_observations",
        "resolver_operators", "vantages", "complete_resolver_vantage_pairs",
        "nxdomain_observations_with_soa", "observation_span_days", "action",
    ]
    with (output_dir / "candidates.csv").open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in report["results"]:
            writer.writerow({
                **row,
                "matched_rules": ";".join(row.get("matched_rules", [])),
                "source_keys": ";".join(row.get("source_keys", [])),
                "resolver_operators": ";".join(row.get("resolver_operators", [])),
                "vantages": ";".join(row.get("vantages", [])),
                "authority_soa_zones": ";".join(row.get("authority_soa_zones", [])),
            })


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline NobleDNS rule-liveness audit (no automatic removals)")
    parser.add_argument("--rules", required=True, type=Path, help="Generated dns-filter.txt")
    parser.add_argument("--observations", required=True, type=Path, help="Versioned DNS observation JSON")
    parser.add_argument("--source-dir", required=True, type=Path, help="Verified source snapshots directory")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--max-age-days", type=int, default=30)
    args = parser.parse_args()
    if args.max_age_days < 1 or args.max_age_days > 365:
        parser.error("--max-age-days must be between 1 and 365")
    now = datetime.now(timezone.utc)
    document = json.loads(args.observations.read_text(encoding="utf-8"))
    observations = validate_observations(document, now)
    rules = load_block_rules(args.rules)
    provenance = load_source_provenance(args.source_dir)
    report = audit(rules, observations, provenance, now, args.max_age_days)
    write_outputs(report, args.output_dir)
    print(
        f"Liveness audit: {report['observed_hostnames']} observed; "
        f"{report['stable_nxdomain_candidates']} stable NXDOMAIN candidates; "
        "automatic removals: 0"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"LIVENESS AUDIT FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
