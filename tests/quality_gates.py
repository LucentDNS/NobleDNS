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
        if not match:
            invalid.append(line)
            continue

        domain = match.group("domain").lower()
        is_exception = bool(match.group("exception"))
        has_caret = bool(match.group("caret"))
        if is_exception and not has_caret:
            invalid.append(line)
            continue
        valid, _reason = mod.valid_domain(domain)
        if not valid:
            invalid.append(line)
            continue

        if is_exception:
            exceptions.add(domain)
        else:
            blocks.add(domain)

    return blocks, exceptions, invalid


def covers(rule_domain: str, hostname: str) -> bool:
    """A parent hostname rule covers the hostname and its subdomains."""
    return hostname == rule_domain or hostname.endswith("." + rule_domain)


def is_blocked(hostname: str, blocks: set[str], exceptions: set[str]) -> bool:
    return (
        any(covers(rule, hostname) for rule in blocks)
        and not any(covers(rule, hostname) for rule in exceptions)
    )


class QualityGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.blocks, cls.exceptions, cls.invalid = load_rules()
        cls.essential = read_domains(ESSENTIAL)
        cls.known_ads = read_domains(KNOWN_ADS)

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
