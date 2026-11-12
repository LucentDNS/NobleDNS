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

RULE_RE = re.compile(r"^(?P<exception>@@)?\|\|(?P<domain>[^\^/$|]+)(?P<caret>\^)?$")
LEADING_DOT_RULE_RE = re.compile(r"^\.(?P<domain>[^\^/$|]+)(?P<caret>\^)?$")


def read_domains(path: Path) -> list[str]:
    return [
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def load_rules() -> tuple[set[str], set[str], list[str]]:
    if not FILTER.is_file():
        raise AssertionError(f"Generated subscription is missing: {FILTER}")

    blocks: set[str] = set()
    exceptions: set[str] = set()
    invalid: list[str] = []

    for raw in FILTER.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        match = RULE_RE.fullmatch(line)
        leading_dot = False
        if not match:
            match = LEADING_DOT_RULE_RE.fullmatch(line)
            leading_dot = bool(match)
        if not match:
            invalid.append(line)
            continue

        domain = match.group("domain").lower()
        is_exception = bool(match.groupdict().get("exception"))
        has_caret = bool(match.group("caret"))
        if is_exception and (not has_caret or leading_dot):
            invalid.append(line)
            continue
        valid, _reason = mod.valid_domain(domain)
        if not valid:
            invalid.append(line)
            continue

        if is_exception:
            exceptions.add(domain)
        elif leading_dot:
            blocks.add("." + domain)
        else:
            blocks.add(domain)

    return blocks, exceptions, invalid


def covers(rule_domain: str, hostname: str) -> bool:
    """Return whether a rule covers a hostname, respecting leading-dot scope."""
    if rule_domain.startswith("."):
        domain = rule_domain[1:]
        return hostname != domain and hostname.endswith("." + domain)
    return hostname == rule_domain or hostname.endswith("." + rule_domain)


def matching_rules(hostname: str, rules: set[str]) -> set[str]:
    labels = hostname.split(".")
    suffixes = {".".join(labels[index:]) for index in range(len(labels))}
    return rules.intersection(suffixes)


def is_blocked(hostname: str, blocks: set[str], exceptions: set[str]) -> bool:
    parent_blocks = {rule for rule in blocks if not rule.startswith(".")}
    subdomain_blocks = {rule[1:] for rule in blocks if rule.startswith(".")}
    parent_match = bool(matching_rules(hostname, parent_blocks))
    subdomain_match = any(
        hostname != domain and hostname.endswith("." + domain)
        for domain in subdomain_blocks
    )
    return (parent_match or subdomain_match) and not bool(
        matching_rules(hostname, exceptions)
    )


class QualityGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.blocks, cls.exceptions, cls.invalid = load_rules()
        cls.essential = read_domains(ESSENTIAL)
        cls.known_ads = read_domains(KNOWN_ADS)

    def test_guard_detects_direct_and_parent_blocks_and_honors_exceptions(self) -> None:
        self.assertTrue(is_blocked("abchina.com", {"abchina.com"}, set()))
        self.assertTrue(is_blocked("mobile.abchina.com", {"abchina.com"}, set()))
        self.assertFalse(
            is_blocked("abchina.com", {"abchina.com"}, {"abchina.com"})
        )
        self.assertFalse(is_blocked("doubleclick.net", set(), set()))

    def test_leading_dot_rule_blocks_subdomains_but_not_apex(self) -> None:
        blocks = {".example.com"}
        self.assertFalse(is_blocked("example.com", blocks, set()))
        self.assertTrue(is_blocked("www.example.com", blocks, set()))
        self.assertTrue(is_blocked("deep.www.example.com", blocks, set()))
        self.assertFalse(is_blocked("notexample.com", blocks, set()))

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
            (hostname, sorted(rule for rule in self.blocks if covers(rule, hostname)),
             sorted(rule for rule in self.exceptions if covers(rule, hostname)))
            for hostname in self.essential
            if is_blocked(hostname, self.blocks, self.exceptions)
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
