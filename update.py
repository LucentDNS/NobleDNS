#!/usr/bin/env python3
"""NobleDNS public DNS filter builder. Pinned dependencies; fail closed."""
from __future__ import annotations
import argparse, csv, hashlib, ipaddress, json, os, re, shutil, socket, sys, tempfile, time
import http.client, urllib.error, urllib.request
import idna
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config" / "sources.json"
PROJECT = "NobleDNS"
VERSION_BASE = "1.0.0"
MAX_RULES = 500_000
def filter_header(version: str) -> str:
    """AdGuard-compatible metadata tied to the build version."""
    return (
        "! Title: NobleDNS Filter\n"
        "! Description: Balanced DNS filtering for ads, trackers and unwanted domains.\n"
        "! Homepage: https://github.com/LucentDNS/NobleDNS\n"
        f"! Version: {version}\n"
        "! Expires: 1 day\n"
        "! Sources: AdGuard DNS Filter, HaGeZi Multi Normal\n"
    )
MIN_SOURCE_BYTES = 100_000
MIN_SOURCE_BLOCKS = 10_000
MAX_SOURCE_BYTES = 50 * 1024 * 1024
TIMEOUT = 120
BLOCK_RE = re.compile(r"^\|\|([^\^/$|]+)\^$")
EXCEPTION_RE = re.compile(r"^@@\|\|([^\^/$|]+)\^$")
BARE_RE = re.compile(r"^\|\|([^\^/$|]+)$")
LEADING_DOT_CARET_RE = re.compile(r"^\.([^\^/$|]+)\^$")
LEADING_DOT_BARE_RE = re.compile(r"^\.([^\^/$|]+)$")
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
IPV4_LIKE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

PROJECT_CODE_LICENSE = "GPL-3.0-only"
LICENSE_PATH = ROOT / "LICENSE"
LICENSE_COPY_PATH = ROOT / "licenses" / "GPL-3.0.txt"
THIRD_PARTY_NOTICES_PATH = ROOT / "THIRD-PARTY-NOTICES.md"

UPSTREAM_LICENSES = {
    "adguard_dns": {
        "spdx": "GPL-3.0",
        "license_url": "https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE",
        "basis": "upstream project license; third-party rights may apply",
    },
    "hagezi_normal": {
        "spdx": "GPL-3.0",
        "license_url": "https://github.com/hagezi/dns-blocklists/blob/main/LICENSE",
        "basis": "upstream project license; third-party input terms may apply",
    },
}


def validate_licensing_files() -> None:
    """Fail closed if required license and attribution files are missing or inconsistent."""
    required = (LICENSE_PATH, LICENSE_COPY_PATH, THIRD_PARTY_NOTICES_PATH)
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError("Required licensing files missing: " + ", ".join(missing))

    license_bytes = LICENSE_PATH.read_bytes()
    license_copy_bytes = LICENSE_COPY_PATH.read_bytes()
    if not license_bytes or license_bytes != license_copy_bytes:
        raise ValueError("LICENSE and licenses/GPL-3.0.txt must be non-empty and byte-identical")

    license_text = license_bytes.decode("utf-8-sig", errors="strict")
    if "GNU GENERAL PUBLIC LICENSE" not in license_text or "Version 3" not in license_text:
        raise ValueError("LICENSE must contain the complete GNU GPL version 3 text")

    notices = THIRD_PARTY_NOTICES_PATH.read_text(encoding="utf-8-sig")
    required_notice_terms = (
        "AdGuard DNS Filter",
        "HaGeZi Multi Normal",
        "GPL-3.0",
        "third-party",
    )
    missing_terms = [term for term in required_notice_terms if term.casefold() not in notices.casefold()]
    if missing_terms:
        raise ValueError("THIRD-PARTY-NOTICES.md is missing required attribution terms: " + ", ".join(missing_terms))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_config(path: Path = CONFIG_PATH) -> dict:
    cfg = json.loads(path.read_text(encoding="utf-8"))
    if cfg.get("project") != PROJECT:
        raise ValueError("config project must be NobleDNS")
    sources = cfg.get("sources")
    if not isinstance(sources, list) or len(sources) != 2:
        raise ValueError("Exactly two configured upstream sources are required")
    keys = [x.get("key") for x in sources]
    if set(keys) != {"adguard_dns", "hagezi_normal"} or len(set(keys)) != 2:
        raise ValueError("Only the approved AdGuard DNS Filter and HaGeZi Multi Normal sources are allowed")
    expected = {
        "adguard_dns": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "hagezi_normal": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt",
    }
    for source in sources:
        if source.get("url") != expected[source["key"]] or not source.get("filename"):
            raise ValueError(f"Unexpected URL or missing filename for {source['key']}")
    if int(cfg.get("max_rules", 0)) != MAX_RULES:
        raise ValueError(f"max_rules must remain {MAX_RULES}")
    return cfg


def valid_domain(raw: str) -> tuple[bool, str]:
    # A trailing dot in these source patterns changes anchor semantics; do not strip it.
    if not raw or raw.endswith(".") or len(raw) > 253:
        return False, "invalid_domain_length_or_trailing_dot"
    domain = raw.lower()
    try:
        ipaddress.ip_address(domain)
        return False, "ip_literal_not_domain"
    except ValueError:
        pass
    if IPV4_LIKE_RE.fullmatch(domain):
        return False, "invalid_or_ip_literal"
    labels = domain.split(".")
    if len(labels) < 2:
        return False, "single_label_not_fqdn"
    if any(not LABEL_RE.fullmatch(label) for label in labels):
        return False, "invalid_domain_label"
    for label in labels:
        if label.startswith("xn--"):
            try:
                # Strict IDNA2008 validation; avoid Python's legacy IDNA2003 codec.
                decoded = idna.decode(label, uts46=False, std3_rules=True)
                encoded = idna.encode(
                    decoded, uts46=False, std3_rules=True
                ).decode("ascii").lower()
                if not decoded or encoded != label:
                    return False, "invalid_punycode_label"
            except (idna.IDNAError, UnicodeError):
                return False, "invalid_punycode_label"
    return True, domain


def classify_non_simple(line: str) -> str:
    low = line.lower()
    if "$badfilter" in low: return "modifier_badfilter"
    if "$important" in low: return "modifier_important"
    if "$" in line: return "other_modifier"
    if "*" in line: return "wildcard_syntax"
    if line.startswith("@@"): return "other_exception_syntax"
    if "/" in line and not line.startswith("//"): return "regex_or_path_syntax"
    if line.startswith("|") or line.endswith("|"): return "other_anchor_syntax"
    if line.startswith("."): return "unsupported_leading_dot_dns_syntax"
    if line.startswith("||") and line.endswith("."): return "other_anchor_syntax"
    if line.startswith("||"): return "other_domain_or_ip_syntax"
    if line.startswith(("0.0.0.0 ", "127.0.0.1 ")): return "hosts_syntax"
    return "other_syntax"


def parse_source(data: bytes, source_key: str, min_blocks: int = MIN_SOURCE_BLOCKS):
    # Strict decoding: replacement characters could silently corrupt a source.
    text = data.decode("utf-8-sig", errors="strict")
    blocks, exceptions = set(), set()
    rejected, rows = Counter(), []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith(("!", "#", "[", "//")):
            continue
        kind, match, bare = "block", BLOCK_RE.fullmatch(line), False
        if not match:
            if line.startswith("."):
                rejected["unsupported_leading_dot_dns_syntax"] += 1
                rows.append((source_key, line_no, "unsupported_leading_dot_dns_syntax", line))
                continue
            m = BARE_RE.fullmatch(line)
            if m and not m.group(1).endswith("."):
                match, bare = m, True
            else:
                match = EXCEPTION_RE.fullmatch(line)
                if match:
                    kind = "exception"
        if match:
            candidate = match.group(1)
            if "*" in candidate:
                reason = "wildcard_syntax"
                rejected[reason] += 1; rows.append((source_key, line_no, reason, line)); continue
            ok, result = valid_domain(candidate)
            if ok:
                if kind == "exception":
                    exceptions.add(f"@@||{result}^")
                else:
                    blocks.add(f"||{result}" + ("" if bare else "^"))
            else:
                rejected[result] += 1; rows.append((source_key, line_no, result, line))
            continue
        reason = classify_non_simple(line)
        rejected[reason] += 1; rows.append((source_key, line_no, reason, line))
    if len(blocks) < min_blocks:
        raise ValueError(f"{source_key}: parsed {len(blocks):,} block rules; minimum is {min_blocks:,}")
    return blocks, exceptions, rejected, rows


def validate_proxy(proxy: str | None) -> str | None:
    """Accept only explicit HTTP(S) proxy URLs without embedded credentials."""
    if proxy is None:
        return None
    from urllib.parse import urlsplit
    parsed = urlsplit(proxy)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Proxy must be an http:// or https:// URL with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Do not embed proxy credentials in --proxy; use a credential-free endpoint")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Proxy URL contains an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Proxy port must be between 1 and 65535")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Proxy URL must not contain a path, query, or fragment")
    return proxy


def fetch(url: str, proxy: str | None) -> bytes:
    proxy = validate_proxy(proxy)
    # Disable ambient proxy discovery: only the explicit CLI value is used.
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})]
    opener = urllib.request.build_opener(*handlers)
    last = None
    for attempt in range(1, 6):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NobleDNS-Updater/1.0", "Accept": "text/plain,*/*;q=0.8", "Cache-Control": "no-cache"})
            with opener.open(req, timeout=TIMEOUT) as resp:
                if getattr(resp, "status", 200) != 200: raise ValueError(f"HTTP status {resp.status}")
                expected = resp.headers.get("Content-Length")
                data = resp.read(MAX_SOURCE_BYTES + 1)
            if len(data) > MAX_SOURCE_BYTES: raise ValueError("source exceeds 50 MiB safety limit")
            if expected and len(data) != int(expected): raise ValueError(f"incomplete response: {len(data)} of {expected} bytes")
            if len(data) < MIN_SOURCE_BYTES: raise ValueError(f"source too small: {len(data)} bytes")
            if data[:500].lstrip().lower().startswith((b"<html", b"<!doctype html")): raise ValueError("HTML response instead of filter list")
            data.decode("utf-8-sig", errors="strict")
            return data
        except (http.client.IncompleteRead, http.client.RemoteDisconnected, ConnectionError, TimeoutError, socket.timeout, urllib.error.URLError, ValueError, UnicodeDecodeError) as exc:
            last = exc
            if attempt < 5: time.sleep(min(2 ** (attempt - 1), 16))
    raise RuntimeError(f"Download failed after 5 attempts: {url}; last error: {last}")


def check_drift(current: dict, current_rules: set[str], previous_manifest: Path | None, max_percent: float, allow_large: bool = False):
    if allow_large or not previous_manifest or not previous_manifest.exists():
        return []
    old = json.loads(previous_manifest.read_text(encoding="utf-8"))
    changes = []
    for key, now in current.items():
        before = old.get("sources", {}).get(key, {}).get("simple_block_rules")
        after = now.get("simple_block_rules")
        if before is None or not before: continue
        pct = abs(after - before) * 100.0 / before
        if pct > max_percent:
            changes.append(f"{key}: parsed blocks changed {before:,} -> {after:,} ({pct:.2f}%), limit {max_percent:.2f}%")
    previous_list = previous_manifest.parent / "dns-filter.txt"
    if previous_list.exists():
        old_rules = {line.strip() for line in previous_list.read_text(encoding="utf-8").splitlines()
                     if line.strip() and not line.lstrip().startswith("!")}
        if old_rules:
            added = len(current_rules - old_rules)
            removed = len(old_rules - current_rules)
            add_pct = added * 100.0 / len(old_rules)
            remove_pct = removed * 100.0 / len(old_rules)
            if add_pct > max_percent or remove_pct > max_percent:
                changes.append(f"main rules changed: +{added:,} ({add_pct:.2f}%), -{removed:,} ({remove_pct:.2f}%); limit {max_percent:.2f}%")
    if changes:
        raise RuntimeError("Source/rule drift gate failed; inspect upstream changes before publishing:\n" + "\n".join(changes))
    return changes


def write_csv(path: Path, header, rows):
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f); w.writerow(header); w.writerows(rows)


def syntax_audit(rules: set[str], source_rules: dict[str, set[str]]):
    """Inventory documented DNS rule forms; flag only forms needing semantic review."""
    forms = {
        "domain_and_subdomains": re.compile(r"^\|\|[^\^/$|]+\^$"),
        "domain_anchor_without_end_boundary": re.compile(r"^\|\|[^\^/$|]+$"),
    }
    semantics = {
        "domain_and_subdomains": "Blocks the domain and all subdomains.",
        "domain_anchor_without_end_boundary": "Valid AdGuard DNS hostname-start anchor; blocks the domain and its subdomains without an explicit end separator.",
    }
    counts = {name: 0 for name in forms}
    examples = {name: [] for name in forms}
    review_rows = []
    for rule in sorted(rules):
        form = next((name for name, pattern in forms.items() if pattern.fullmatch(rule)), "unclassified")
        if form == "unclassified":
            raise ValueError(f"Rule missing from syntax audit: {rule}")
        counts[form] += 1
        if len(examples[form]) < 10:
            examples[form].append(rule)
        if form == "domain_anchor_without_end_boundary":
            sources = [key for key, source_set in source_rules.items() if rule in source_set]
            review_rows.append((rule, form, semantics[form], ";".join(sources)))
    return {
        "total": len(rules),
        "forms": counts,
        "semantics": semantics,
        "review_required": counts["domain_anchor_without_end_boundary"],
        "examples": examples,
    }, review_rows


def parse_allowlist(path: Path) -> set[str]:
    """Load the project-maintained exact-domain allowlist; invalid entries fail closed."""
    if not path.is_file():
        raise FileNotFoundError(f"Project allowlist file is required: {path}")
    domains = set()
    for line_no, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if any(ch in line for ch in "/^$|*") or line.startswith("."):
            raise ValueError(f"Invalid allowlist entry at {path}:{line_no}: expected an exact domain")
        ok, normalized = valid_domain(line)
        if not ok:
            raise ValueError(f"Invalid allowlist domain at {path}:{line_no}: {normalized}")
        if normalized in domains:
            raise ValueError(f"Duplicate allowlist domain at {path}:{line_no}: {normalized}")
        domains.add(normalized)
    return domains


def apply_allowlist(block_rules: set[str], allowlist_domains: set[str]):
    """Remove matching blocks and emit explicit AdGuard exception rules."""
    active_exceptions = {f"@@||{domain}^" for domain in allowlist_domains}
    kept = set()
    for rule in block_rules:
        match = BLOCK_RE.fullmatch(rule) or BARE_RE.fullmatch(rule)
        if not match:
            raise ValueError(f"Unexpected block rule before allowlist application: {rule}")
        domain = match.group(1)
        if any(domain == allowed or domain.endswith("." + allowed) for allowed in allowlist_domains):
            continue
        kept.add(rule)
    return kept, active_exceptions


def build(args) -> Path:
    validate_licensing_files()
    cfg = load_config(Path(args.config))
    now = datetime.now(timezone.utc)
    version = VERSION_BASE
    allowlist_path = ROOT / "config" / "allowlist.txt"
    allowlist_domains = parse_allowlist(allowlist_path)
    parsed, exceptions, source_stats, rejected_rows, raw_snapshots = {}, {}, {}, [], {}
    input_dir = Path(args.input_dir) if args.input_dir else None
    for source in cfg["sources"]:
        key, filename = source["key"], source["filename"]
        if input_dir:
            p = input_dir / filename
            if not p.is_file(): raise FileNotFoundError(f"Missing input snapshot: {p}")
            data = p.read_bytes()
        else:
            data = fetch(source["url"], args.proxy)
        if len(data) < MIN_SOURCE_BYTES: raise ValueError(f"{key}: source smaller than {MIN_SOURCE_BYTES} bytes")
        raw_snapshots[filename] = data
        blocks, exc, rejected, rows = parse_source(data, key)
        parsed[key], exceptions[key] = blocks, exc
        rejected_rows.extend(rows)
        license_info = UPSTREAM_LICENSES[key]
        source_stats[key] = {"name": source["name"], "url": source["url"], "license": license_info["spdx"], "license_url": license_info["license_url"], "license_basis": license_info["basis"], "bytes": len(data), "sha256": sha256(data), "simple_block_rules": len(blocks), "simple_exception_rules": len(exc), "excluded_lines_by_reason": dict(rejected)}
        print(f"{key}: {len(blocks):,} blocks, {len(exc):,} exceptions, {sum(rejected.values()):,} excluded")
    keys = [x["key"] for x in cfg["sources"]]
    source_merged = parsed[keys[0]] | parsed[keys[1]]
    check_drift(source_stats, source_merged, Path(args.previous_manifest) if args.previous_manifest else None, args.max_source_change_percent, args.allow_large_change)
    common = parsed[keys[0]] & parsed[keys[1]]
    merged, active_allowlist_rules = apply_allowlist(source_merged, allowlist_domains)
    if len(merged) + len(active_allowlist_rules) > MAX_RULES:
        raise RuntimeError(
            f"Total active rule cap exceeded: {len(merged) + len(active_allowlist_rules):,} > {MAX_RULES:,}"
        )
    syntax_summary, syntax_review_rows = syntax_audit(merged, parsed)
    if not merged: raise RuntimeError("Refusing empty output")
    all_exceptions = exceptions[keys[0]] | exceptions[keys[1]]
    main = filter_header(version) + "\n".join(sorted(merged | active_allowlist_rules)) + "\n"
    main_bytes = main.encode("utf-8")
    # Validate every published line against the explicit syntax allowlist.
    lines = [x for x in main.splitlines() if x and not x.startswith("!")]
    expected_lines = merged | active_allowlist_rules
    if len(lines) != len(expected_lines) or len(set(lines)) != len(lines):
        raise RuntimeError("Output count/duplicate validation failed")
    for line in lines:
        m = BLOCK_RE.fullmatch(line) or BARE_RE.fullmatch(line) or EXCEPTION_RE.fullmatch(line)
        if not m: raise RuntimeError(f"Unsupported output syntax: {line}")
        ok, reason = valid_domain(m.group(1))
        if not ok: raise RuntimeError(f"Invalid output domain ({reason}): {line}")
        if line.startswith("@@") and line not in active_allowlist_rules:
            raise RuntimeError(f"Unapproved exception rule in main output: {line}")
    manifest = {"project": PROJECT, "version": version, "status": "PUBLIC", "release_channel": cfg.get("release_channel", "public"), "built_at_utc": now.isoformat(), "licensing": {"original_project_code": {"spdx": PROJECT_CODE_LICENSE, "license_file": "LICENSE"}, "upstream_rule_data": [{"key": source["key"], "name": source["name"], "spdx": UPSTREAM_LICENSES[source["key"]]["spdx"], "license_url": UPSTREAM_LICENSES[source["key"]]["license_url"], "qualification": UPSTREAM_LICENSES[source["key"]]["basis"]} for source in cfg["sources"]], "third_party_notices": "THIRD-PARTY-NOTICES.md", "compiled_data_notice": "Contains upstream-derived rule material; applicable upstream licenses and third-party rights remain relevant. NobleDNS does not claim the compiled data is wholly original."}, "sources": source_stats, "source_merged_blocking_rules": len(source_merged), "blocking_rules": len(merged), "allowlist_removed_blocking_rules": len(source_merged) - len(merged), "active_allowlist_rules": len(active_allowlist_rules), "allowlist_domains": sorted(allowlist_domains), "common_rules": len(common), "source_only_rules": {keys[0]: len(parsed[keys[0]] - parsed[keys[1]]), keys[1]: len(parsed[keys[1]] - parsed[keys[0]])}, "exception_rules_separate": len(all_exceptions), "max_rules": MAX_RULES, "main_subscription_sha256": sha256(main_bytes), "syntax_audit": syntax_summary, "policy": {"main_list": "block-only", "upstream_exceptions": "separate review artifact; never activated automatically", "project_allowlist": "exact entries in config/allowlist.txt generate active @@||domain^ exceptions", "complex_syntax": "excluded unless semantic equivalence is proven", "bare_domain_anchor": "valid AdGuard DNS syntax; preserved unchanged", "leading_dot_domain_anchor": "excluded from public output as unsupported by the selected syntax contract", "source_drift_gate_percent": args.max_source_change_percent}}
    report = [f"{PROJECT} build report", f"Version: {version}", "Status: PUBLIC", f"Original project code license: {PROJECT_CODE_LICENSE}", "Upstream rule data: GPL-3.0 as declared by the upstream projects; third-party rights may apply.", "Attribution: see THIRD-PARTY-NOTICES.md and LICENSE.", f"Merged block rules: {len(merged):,}", f"Common rules: {len(common):,}", f"Upstream exceptions (review only): {len(all_exceptions):,}", f"Active project allowlist rules: {len(active_allowlist_rules):,}", f"Rule cap: {len(merged):,}/{MAX_RULES:,}", f"Main SHA256: {manifest['main_subscription_sha256']}", "", "Checks passed: source size, strict UTF-8, minimum parsed rules, source drift gate, supported AdGuard DNS syntax, active allowlist validation, uniqueness, rule cap.", "Ongoing maintenance: review user reports, investigate compatibility issues, and add confirmed cases to regression tests."]
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=True)
    temp_parent = Path(tempfile.mkdtemp(prefix=".nobledns-stage-", dir=out))
    try:
        stage = temp_parent / "latest"; stage.mkdir()
        (stage / "dns-filter.txt").write_bytes(main_bytes)
        (stage / "NobleDNS.txt").write_bytes(main_bytes)
        shutil.copy2(allowlist_path, stage / "project-allowlist.txt")
        shutil.copy2(LICENSE_PATH, stage / "LICENSE")
        shutil.copy2(THIRD_PARTY_NOTICES_PATH, stage / "THIRD-PARTY-NOTICES.md")
        staged_licenses = stage / "licenses"; staged_licenses.mkdir()
        shutil.copy2(LICENSE_COPY_PATH, staged_licenses / "GPL-3.0.txt")
        (stage / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (stage / "validation-report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
        (stage / "whitelist-review.txt").write_text("! Source exceptions for manual review only; not active in dns-filter.txt\n" + "\n".join(sorted(all_exceptions)) + ("\n" if all_exceptions else ""), encoding="utf-8")
        write_csv(stage / "parser-exclusions.csv", ["source", "line_number", "exclusion_reason", "original_line"], sorted(rejected_rows))
        write_csv(stage / "syntax-review.csv", ["rule", "syntax_form", "documented_semantics", "source"], syntax_review_rows)
        (stage / "syntax-audit.json").write_text(json.dumps(syntax_summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        source_dir = stage / "sources"; source_dir.mkdir()
        source_manifest = {}
        for source in cfg["sources"]:
            filename = source["filename"]; data = raw_snapshots[filename]
            (source_dir / filename).write_bytes(data)
            license_info = UPSTREAM_LICENSES[source["key"]]
            source_manifest[source["key"]] = {"filename": filename, "url": source["url"], "license": license_info["spdx"], "license_url": license_info["license_url"], "license_basis": license_info["basis"], "bytes": len(data), "sha256": sha256(data)}
        (source_dir / "sources-manifest.json").write_text(json.dumps(source_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        # Validate staged bytes before swapping latest; keep previous latest intact on failure.
        staged = (stage / "dns-filter.txt").read_bytes()
        if sha256(staged) != manifest["main_subscription_sha256"]: raise RuntimeError("Staged SHA256 mismatch")
        if (stage / "NobleDNS.txt").read_bytes() != staged: raise RuntimeError("Legacy subscription differs from canonical output")
        latest = out / "latest"; backup = out / ".latest-previous"
        if backup.exists(): shutil.rmtree(backup)
        if latest.exists(): os.replace(latest, backup)
        try: os.replace(stage, latest)
        except Exception:
            if backup.exists() and not latest.exists(): os.replace(backup, latest)
            raise
        if backup.exists(): shutil.rmtree(backup)
    finally:
        shutil.rmtree(temp_parent, ignore_errors=True)
    print(f"BUILD SUCCESS: {version}; {len(merged):,} rules; {out / 'latest'}")
    return out / "latest"


def main():
    p = argparse.ArgumentParser(description="NobleDNS fail-closed rule builder")
    p.add_argument("--config", default=str(CONFIG_PATH))
    p.add_argument("--proxy")
    p.add_argument("--out", default="build-output")
    p.add_argument("--input-dir", help="Offline source snapshots directory")
    p.add_argument("--previous-manifest", help="Last published manifest for source drift checks")
    p.add_argument("--max-source-change-percent", type=float, default=15.0)
    p.add_argument("--allow-large-change", action="store_true", help="Manual override; inspect upstream changes first")
    args = p.parse_args()
    if not 0 < args.max_source_change_percent <= 100: p.error("--max-source-change-percent must be >0 and <=100")
    build(args)

if __name__ == "__main__":
    try: main()
    except Exception as exc:
        print(f"BUILD FAILED: {exc}", file=sys.stderr)
        print("No successful output was published by this build.", file=sys.stderr)
        sys.exit(1)
