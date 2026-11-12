#!/usr/bin/env python3
"""NobleDNS public DNS filter builder. Pinned dependencies; fail closed."""
from __future__ import annotations
import argparse, csv, hashlib, ipaddress, json, os, re, shutil, socket, sys, tempfile, time
import http.client, urllib.error, urllib.request
from urllib.parse import urlsplit
import idna
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config" / "sources.json"
PROJECT = "NobleDNS"
VERSION_BASE = "1.0.3"
MAX_RULES = 500_000
FILTER_HEADER = (
    "! Title: NobleDNS Filter\n"
    "! Description: DNS filtering for ads, trackers, telemetry and unwanted domains.\n"
    "! Homepage: https://github.com/LucentDNS/NobleDNS\n"
    f"! Version: {VERSION_BASE}\n"
    "! Expires: 1 day\n"
    "! Sources: AdGuard DNS Filter, HaGeZi Multi Normal\n"
    "! License: GPL-3.0-only (code); upstream rule data: GPL-3.0 (see THIRD-PARTY-NOTICES; third-party rights may apply).\n"
    "! Content: Listed domains are included as blocking targets only.\n"
)
MIN_SOURCE_BYTES = 100_000
MIN_SOURCE_BLOCKS = 10_000
MAX_SOURCE_BYTES = 50 * 1024 * 1024
TIMEOUT = 120
BLOCK_RE = re.compile(r"^\|\|([^\^/$|]+)\^$")
EXCEPTION_RE = re.compile(r"^@@\|\|([^\^/$|]+)\^$")
BARE_RE = re.compile(r"^\|\|([^\^/$|]+)$")
LEADING_DOT_RE = re.compile(r"^\.([^\^/$|]+)(\^)?$")
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
        leading_dot = LEADING_DOT_RE.fullmatch(line)
        if leading_dot:
            candidate = leading_dot.group(1)
            ok, result = valid_domain(candidate)
            if ok:
                blocks.add("." + result + ("^" if leading_dot.group(2) else ""))
            else:
                rejected[result] += 1
                rows.append((source_key, line_no, result, line))
            continue
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
        if line.startswith("."):
            reason = "unsupported_leading_dot_dns_syntax"
            rejected[reason] += 1
            rows.append((source_key, line_no, reason, line))
            continue
        kind, match, bare = "block", BLOCK_RE.fullmatch(line), False
        if not match:
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


def validate_proxy_url(proxy: str | None) -> str | None:
    """Accept only explicit HTTP(S) proxy endpoints without embedded credentials."""
    if proxy is None or not proxy.strip():
        return None
    try:
        parsed = urlsplit(proxy)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid proxy URL: malformed host or port") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Invalid proxy URL: only explicit http:// or https:// endpoints are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Proxy credentials must not be embedded in the command-line URL")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Invalid proxy URL: paths, queries and fragments are not supported")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid proxy URL: port must be between 1 and 65535")
    return proxy


def fetch(url: str, proxy: str | None) -> bytes:
    proxy = validate_proxy_url(proxy)
    # Use only an explicitly supplied proxy; do not silently inherit ambient proxy settings.
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})]
    opener = urllib.request.build_opener(*handlers)
    last = None
    for attempt in range(1, 6):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NobleDNS-Updater/1.0", "Accept": "text/plain,*/*;q=0.8", "Cache-Control": "no-cache"})
            with opener.open(req, timeout=TIMEOUT) as resp:
                if getattr(resp, "status", 200) != 200: raise ValueError(f"HTTP status {resp.status}")
                if urlsplit(resp.geturl()).scheme.lower() != "https":
                    raise ValueError("Source redirected away from HTTPS; refusing downgrade")
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


MAX_ABSOLUTE_RULE_DELTA = 3000


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
            if added > MAX_ABSOLUTE_RULE_DELTA or removed > MAX_ABSOLUTE_RULE_DELTA:
                changes.append(
                    f"main rules changed: +{added:,} ({add_pct:.2f}%), "
                    f"-{removed:,} ({remove_pct:.2f}%); absolute limit "
                    f"{MAX_ABSOLUTE_RULE_DELTA:,} additions/removals"
                )
            elif add_pct > max_percent or remove_pct > max_percent:
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
        "subdomains_only": re.compile(r"^\.[^\^/$|]+\^$"),
        "subdomains_only_without_end_boundary": re.compile(r"^\.[^\^/$|]+$"),
    }
    semantics = {
        "domain_and_subdomains": "Blocks the domain and all subdomains.",
        "domain_anchor_without_end_boundary": "Valid hostname-start anchor that also matches subdomains, without an explicit hostname-end separator (^); suffix-like hostnames may also match and require compatibility review.",
        "subdomains_only": "Matches subdomains of the named domain but not the apex; ^ marks the end of the hostname.",
        "subdomains_only_without_end_boundary": "Matches subdomains of the named domain but not the apex, without an explicit hostname-end separator (^); suffix-like hostnames may also match and require compatibility review.",
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
        if form in {"domain_anchor_without_end_boundary", "subdomains_only_without_end_boundary"}:
            sources = [key for key, source_set in source_rules.items() if rule in source_set]
            review_rows.append((rule, form, semantics[form], ";".join(sources)))
    return {
        "total": len(rules),
        "forms": counts,
        "semantics": semantics,
        "review_required": (counts["domain_anchor_without_end_boundary"] + counts["subdomains_only_without_end_boundary"]),
        "examples": examples,
    }, review_rows


def resolve_subscription_last_modified(
    rules: set[str],
    previous_manifest: Path | None,
    now: datetime,
) -> str:
    """Keep the date stable for identical rule content; advance it on rule changes."""
    if previous_manifest and previous_manifest.is_file():
        previous_list = previous_manifest.parent / "dns-filter.txt"
        if previous_list.is_file():
            previous_lines = previous_list.read_text(encoding="utf-8").splitlines()
            previous_rules = {
                line.strip()
                for line in previous_lines
                if line.strip() and not line.lstrip().startswith("!")
            }
            if previous_rules == rules:
                for line in previous_lines:
                    match = re.fullmatch(r"! Last modified: (\d{4}-\d{2}-\d{2}) \(UTC\)", line.strip())
                    if match:
                        return match.group(1)
                try:
                    old_manifest = json.loads(previous_manifest.read_text(encoding="utf-8"))
                    built_at = datetime.fromisoformat(old_manifest["built_at_utc"])
                    return built_at.astimezone(timezone.utc).date().isoformat()
                except (KeyError, TypeError, ValueError):
                    pass
    return now.astimezone(timezone.utc).date().isoformat()


def render_subscription(
    blocks: set[str],
    exceptions: set[str],
    last_modified: str | None = None,
) -> str:
    """Render the canonical filter while preserving active exception semantics."""
    if last_modified is None:
        last_modified = datetime.now(timezone.utc).date().isoformat()
    if blocks & exceptions:
        raise ValueError("A rule cannot be both a blocking rule and an exception")
    rules = blocks | exceptions
    if not rules:
        raise ValueError("Refusing an empty subscription")
    metadata = (
        f"! Last modified: {last_modified} (UTC)\n"
        f"! Blocked domains: {len(blocks):,}\n\n"
    )
    return FILTER_HEADER + metadata + "\n".join(sorted(rules)) + "\n"


def build(args) -> Path:
    validate_licensing_files()
    cfg = load_config(Path(args.config))
    now = datetime.now(timezone.utc)
    version = VERSION_BASE
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
    merged = parsed[keys[0]] | parsed[keys[1]]
    all_exceptions = exceptions[keys[0]] | exceptions[keys[1]]
    published_rules = merged | all_exceptions
    previous_manifest = Path(args.previous_manifest) if args.previous_manifest else None
    check_drift(source_stats, published_rules, previous_manifest, args.max_source_change_percent, args.allow_large_change)
    last_modified = resolve_subscription_last_modified(published_rules, previous_manifest, now)
    common = parsed[keys[0]] & parsed[keys[1]]
    syntax_summary, syntax_review_rows = syntax_audit(merged, parsed)
    if len(published_rules) > MAX_RULES: raise RuntimeError(f"Rule cap exceeded: {len(published_rules):,} > {MAX_RULES:,}")
    if not merged: raise RuntimeError("Refusing empty output")
    main = render_subscription(merged, all_exceptions, last_modified)
    main_bytes = main.encode("utf-8")
    # Validate every published blocking and exception rule without rewriting its syntax.
    lines = [x for x in main.splitlines() if x and not x.startswith("!")]
    if len(lines) != len(published_rules) or len(set(lines)) != len(lines): raise RuntimeError("Output count/duplicate validation failed")
    for line in lines:
        m = EXCEPTION_RE.fullmatch(line) or BLOCK_RE.fullmatch(line) or BARE_RE.fullmatch(line) or LEADING_DOT_RE.fullmatch(line)
        if not m: raise RuntimeError(f"Unexpected output syntax: {line}")
        ok, reason = valid_domain(m.group(1))
        if not ok: raise RuntimeError(f"Invalid output domain ({reason}): {line}")
    manifest = {"project": PROJECT, "version": version, "status": "PUBLIC", "release_channel": cfg.get("release_channel", "public"), "built_at_utc": now.isoformat(), "subscription_last_modified": last_modified, "licensing": {"original_project_code": {"spdx": PROJECT_CODE_LICENSE, "license_file": "LICENSE"}, "upstream_rule_data": [{"key": source["key"], "name": source["name"], "spdx": UPSTREAM_LICENSES[source["key"]]["spdx"], "license_url": UPSTREAM_LICENSES[source["key"]]["license_url"], "qualification": UPSTREAM_LICENSES[source["key"]]["basis"]} for source in cfg["sources"]], "third_party_notices": "THIRD-PARTY-NOTICES.md", "compiled_data_notice": "Contains upstream-derived rule material; applicable upstream licenses and third-party rights remain relevant. NobleDNS does not claim the compiled data is wholly original."}, "sources": source_stats, "blocking_rules": len(merged), "active_exception_rules": len(all_exceptions), "active_exception_rules_by_source": {key: len(exceptions[key]) for key in keys}, "main_subscription_rules": len(published_rules), "common_rules": len(common), "source_only_rules": {keys[0]: len(parsed[keys[0]] - parsed[keys[1]]), keys[1]: len(parsed[keys[1]] - parsed[keys[0]])}, "exception_rules_separate": 0, "max_rules": MAX_RULES, "main_subscription_sha256": sha256(main_bytes), "syntax_audit": syntax_summary, "policy": {"main_list": "blocking-and-exception", "exceptions": "simple upstream exceptions active in the main subscription; complex exception syntax remains excluded pending review", "complex_syntax": "excluded unless semantic equivalence is proven", "bare_domain_anchor": "preserved unchanged", "leading_dot_domain_anchor": "preserved unchanged; matches subdomains only, not the apex", "source_drift_gate_percent": args.max_source_change_percent}}
    report = [f"{PROJECT} build report", f"Version: {version}", "Status: PUBLIC", f"Original project code license: {PROJECT_CODE_LICENSE}", "Upstream rule data: GPL-3.0 as declared by the upstream projects; third-party rights may apply.", "Attribution: see THIRD-PARTY-NOTICES.md and LICENSE.", f"Merged block rules: {len(merged):,}", f"Common rules: {len(common):,}", f"Active exception rules: {len(all_exceptions):,}", f"Main subscription rules: {len(published_rules):,}", f"Subscription last modified (UTC): {last_modified}", f"Rule cap: {len(published_rules):,}/{MAX_RULES:,}", f"Main SHA256: {manifest['main_subscription_sha256']}", "", "Checks passed: source size, strict UTF-8, minimum parsed rules, source drift gate, syntax/domain validation, active exception validation, subscription/allowlist parity, uniqueness and rule cap.", "Ongoing maintenance: review user reports, investigate compatibility issues, and add confirmed cases to regression tests."]
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=True)
    temp_parent = Path(tempfile.mkdtemp(prefix=".nobledns-stage-", dir=out))
    try:
        stage = temp_parent / "latest"; stage.mkdir()
        (stage / "dns-filter.txt").write_bytes(main_bytes)
        # Compatibility path: byte-identical to the canonical subscription.
        (stage / "NobleDNS.txt").write_bytes(main_bytes)
        shutil.copy2(LICENSE_PATH, stage / "LICENSE")
        shutil.copy2(THIRD_PARTY_NOTICES_PATH, stage / "THIRD-PARTY-NOTICES.md")
        staged_licenses = stage / "licenses"; staged_licenses.mkdir()
        shutil.copy2(LICENSE_COPY_PATH, staged_licenses / "GPL-3.0.txt")
        (stage / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (stage / "validation-report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
        active_allowlist_lines = ["! Simple upstream exception rules active in dns-filter.txt; complex exception syntax remains excluded."]
        for key in keys:
            if exceptions[key]:
                active_allowlist_lines.append(f"! Source: {key}")
                active_allowlist_lines.extend(sorted(exceptions[key]))
        (stage / "allowlist-active.txt").write_text("\n".join(active_allowlist_lines) + "\n", encoding="utf-8")
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
        if (stage / "NobleDNS.txt").read_bytes() != staged:
            raise RuntimeError("Legacy subscription mirror differs from canonical output")
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
