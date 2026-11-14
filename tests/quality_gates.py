"""Build-artifact quality gates for the published NobleDNS subscription."""
from __future__ import annotations

import os
import re
import unittest
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("nobledns_quality_update", Path(__file__).resolve().parents[1] / "update.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

ROOT = Path(__file__).resolve().parents[1]
FILTER = Path(os.environ.get(
    "NOBLEDNS_FILTER_PATH",
    str(ROOT / "build-output" / "latest" / "dns-filter.txt"),
))
if not FILTER.is_absolute():
    FILTER = ROOT / FILTER

ESSENTIAL = ROOT / "tests" / "fixtures" / "essential-domains.txt"
KNOWN_ADS = ROOT / "tests" / "fixtures" / "known-ads.txt"

RULE_RE = re.compile(r"^(?P<exception>@@)?\|\|(?P<domain>[^\^/$|]+)(?P<caret>\^)?(?P<important>\$important)?$")


def read_domains(path: Path) -> list[str]:
    return [
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def load_rules() -> tuple[set[str], set[str], set[str], list[str]]:
    if not FILTER.is_file():
        raise AssertionError(f"Generated subscription is missing: {FILTER}")

    blocks: set[str] = set()
    exceptions: set[str] = set()
    important_blocks: set[str] = set()
    invalid: list[str] = []

    for raw in FILTER.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        match = RULE_RE.fullmatch(line)
        if not match:
            invalid.append(line)
            continue

        domain = match.group("domain").lower()
        is_exception = bool(match.group("exception"))
        has_caret = bool(match.group("caret"))
        is_important = bool(match.group("important"))
        if is_exception and (not has_caret or is_important):
            invalid.append(line)
            continue
        if is_important and not has_caret:
            invalid.append(line)
            continue

        if "*" in domain:
            valid, _reason = mod.valid_wildcard_pattern(domain)
        else:
            valid, _reason = mod.valid_domain(domain)
        if not valid:
            invalid.append(line)
            continue

        if is_exception:
            exceptions.add(domain)
        else:
            blocks.add(domain)
            if is_important:
                important_blocks.add(domain)

    return blocks, exceptions, important_blocks, invalid


def matching_rules(hostname: str, rules: set[str]) -> set[str]:
    """Return rules matching the hostname or one of its parent-domain suffixes."""
    labels = hostname.lower().split(".")
    suffixes = {".".join(labels[index:]) for index in range(len(labels))}
    matched: set[str] = set()
    for rule in rules:
        if "*" not in rule:
            if rule in suffixes:
                matched.add(rule)
            continue
        pattern = re.compile("^" + re.escape(rule).replace(r"\*", ".*") + "$")
        if any(pattern.fullmatch(suffix) for suffix in suffixes):
            matched.add(rule)
    return matched


def is_blocked(
    hostname: str,
    blocks: set[str],
    exceptions: set[str],
    important_blocks: set[str] | None = None,
) -> bool:
    block_matches = matching_rules(hostname, blocks)
    if not block_matches:
        return False
    exception_matches = matching_rules(hostname, exceptions)
    important_matches = matching_rules(hostname, important_blocks or set())
    return bool(important_matches) or not bool(exception_matches)


class QualityGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.blocks, cls.exceptions, cls.important_blocks, cls.invalid = load_rules()
        cls.essential = read_domains(ESSENTIAL)
        cls.known_ads = read_domains(KNOWN_ADS)

    def test_guard_detects_direct_and_parent_blocks_and_honors_exceptions(self) -> None:
        self.assertTrue(is_blocked("abchina.com", {"abchina.com"}, set()))
        self.assertTrue(is_blocked("mobile.abchina.com", {"abchina.com"}, set()))
        self.assertFalse(
            is_blocked("abchina.com", {"abchina.com"}, {"abchina.com"})
        )
        self.assertFalse(is_blocked("doubleclick.net", set(), set()))

    def test_wildcard_rules_match_hostname_suffixes(self) -> None:
        rules = {"ad*.example.com", "*.wild.example.net"}
        self.assertEqual(
            matching_rules("ad-sdk.example.com", rules),
            {"ad*.example.com"},
        )
        self.assertEqual(
            matching_rules("child.ad-sdk.example.com", rules),
            {"ad*.example.com"},
        )
        self.assertEqual(matching_rules("wild.example.net", rules), set())

    def test_important_block_overrides_matching_exception(self) -> None:
        blocks = {"ads.example.com"}
        exceptions = {"example.com"}
        self.assertFalse(is_blocked("ads.example.com", blocks, exceptions))
        self.assertTrue(
            is_blocked("ads.example.com", blocks, exceptions, {"ads.example.com"})
        )

    def test_exception_count_stays_small(self) -> None:
        """Exceptions are allow-rules; a sudden surge means the list is leaking."""
        self.assertLessEqual(
            len(self.exceptions),
            50,
            f"{len(self.exceptions)} exceptions active — review upstream before publishing",
        )

    def test_fixture_sizes_are_explicit_and_stable(self) -> None:
        self.assertEqual(len(self.essential), 72)
        self.assertEqual(len(set(self.essential)), 72)
        self.assertEqual(len(self.known_ads), 20)
        self.assertEqual(len(set(self.known_ads)), 20)

    def test_published_subscription_contains_only_supported_syntax(self) -> None:
        self.assertFalse(
            self.invalid,
            f"{len(self.invalid)} unsupported/malformed rule(s); first 10: {self.invalid[:10]}",
        )
        self.assertGreater(len(self.blocks), 200_000)
        self.assertLessEqual(len(self.blocks) + len(self.exceptions), 500_000)

    def test_no_essential_hostname_is_effectively_blocked(self) -> None:
        affected = [
            (hostname, sorted(matching_rules(hostname, self.blocks)),
             sorted(matching_rules(hostname, self.exceptions)))
            for hostname in self.essential
            if is_blocked(hostname, self.blocks, self.exceptions, self.important_blocks)
        ]
        self.assertFalse(
            affected,
            f"{len(affected)} essential hostname(s) blocked; first 10: {affected[:10]}",
        )

    def test_known_ad_infrastructure_remains_blocked(self) -> None:
        missing = [
            hostname for hostname in self.known_ads
            if not is_blocked(hostname, self.blocks, self.exceptions)
        ]
        self.assertFalse(
            missing,
            f"{len(missing)} known ad hostname(s) no longer blocked: {missing}",
        )
