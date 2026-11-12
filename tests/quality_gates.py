"""Build-artifact quality gates for the published NobleDNS subscription."""
from __future__ import annotations

import json
import os
import re
import unittest
import importlib.util
from pathlib import Path

from tools.validate_evidence_corpus import validate_corpus

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
EVIDENCE_CORPUS = ROOT / "tests" / "fixtures" / "evidence-corpus.json"

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
    bare_blocks: set[str] = set()
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
        elif has_caret:
            blocks.add(domain)
        else:
            bare_blocks.add(domain)

    return blocks, bare_blocks, exceptions, invalid


def covers(rule_domain: str, hostname: str) -> bool:
    """A parent hostname rule covers the hostname and its subdomains."""
    return hostname == rule_domain or hostname.endswith("." + rule_domain)


def matching_rules(hostname: str, rules: set[str]) -> set[str]:
    """Match rules with an explicit ^ hostname-end boundary."""
    labels = hostname.split(".")
    suffixes = {".".join(labels[index:]) for index in range(len(labels))}
    return rules.intersection(suffixes)


def matching_bare_rules(hostname: str, rules: set[str]) -> set[str]:
    """Match ||domain rules without ^: domain anchor, but no hostname-end boundary."""
    return {
        rule for rule in rules
        if hostname == rule or hostname.startswith(rule) or f".{rule}" in hostname
    }


def is_blocked(
    hostname: str,
    blocks: set[str],
    exceptions: set[str],
    bare_blocks: set[str] | None = None,
) -> bool:
    block_matches = matching_rules(hostname, blocks)
    if bare_blocks:
        block_matches |= matching_bare_rules(hostname, bare_blocks)
    return bool(block_matches) and not bool(matching_rules(hostname, exceptions))


class QualityGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.blocks, cls.bare_blocks, cls.exceptions, cls.invalid = load_rules()
        cls.essential = read_domains(ESSENTIAL)
        cls.known_ads = read_domains(KNOWN_ADS)
        cls.evidence_corpus = json.loads(EVIDENCE_CORPUS.read_text(encoding="utf-8"))
        corpus_errors = validate_corpus(cls.evidence_corpus)
        if corpus_errors:
            raise AssertionError("Invalid evidence corpus: " + "; ".join(corpus_errors))

    def test_guard_detects_direct_and_parent_blocks_and_honors_exceptions(self) -> None:
        self.assertTrue(is_blocked("abchina.com", {"abchina.com"}, set()))
        self.assertTrue(is_blocked("mobile.abchina.com", {"abchina.com"}, set()))
        self.assertFalse(
            is_blocked("abchina.com", {"abchina.com"}, {"abchina.com"})
        )
        self.assertFalse(is_blocked("doubleclick.net", set(), set()))

    def test_supported_exception_scope_is_suffix_aware(self) -> None:
        # This models the simple supported ||domain^ / @@||domain^ subset.
        # Modifiers such as $important are rejected by the production parser.
        blocks = {"example.com", "ads.child.example.net"}
        exceptions = {"safe.example.com", "example.net"}
        self.assertFalse(is_blocked("safe.example.com", blocks, exceptions))
        self.assertFalse(is_blocked("cdn.safe.example.com", blocks, exceptions))
        self.assertFalse(is_blocked("ads.child.example.net", blocks, exceptions))
        self.assertFalse(is_blocked("x.ads.child.example.net", blocks, exceptions))
        self.assertTrue(is_blocked("other.example.com", blocks, exceptions))
        self.assertTrue(is_blocked("example.com", blocks, exceptions))
        self.assertFalse(is_blocked("notexample.com", blocks, exceptions))

    def test_bare_anchor_without_caret_has_no_end_boundary(self) -> None:
        bare = {"bare.example.com"}
        self.assertTrue(is_blocked("bare.example.com", set(), set(), bare))
        self.assertTrue(is_blocked("child.bare.example.com", set(), set(), bare))
        # || is a hostname anchor; without ^ it can continue matching after the domain text.
        self.assertTrue(is_blocked("bare.example.com.evil.test", set(), set(), bare))
        self.assertTrue(is_blocked("x.bare.example.com.evil.test", set(), set(), bare))
        self.assertFalse(is_blocked("notbare.example.com", set(), set(), bare))
        self.assertFalse(is_blocked("notbare.example.com.evil.test", set(), set(), bare))

    def test_caret_rule_requires_hostname_boundary(self) -> None:
        blocks = {"bare.example.com"}
        self.assertTrue(is_blocked("bare.example.com", blocks, set()))
        self.assertTrue(is_blocked("child.bare.example.com", blocks, set()))
        self.assertFalse(is_blocked("bare.example.com.evil.test", blocks, set()))
        self.assertFalse(is_blocked("notbare.example.com", blocks, set()))

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
            (
                hostname,
                sorted(matching_rules(hostname, self.blocks) | matching_bare_rules(hostname, self.bare_blocks)),
                sorted(matching_rules(hostname, self.exceptions)),
            )
            for hostname in self.essential
            if is_blocked(hostname, self.blocks, self.exceptions, self.bare_blocks)
        ]
        self.assertFalse(
            affected,
            f"{len(affected)} essential hostname(s) blocked; first 10: {affected[:10]}",
        )

    def test_known_ad_infrastructure_remains_blocked(self) -> None:
        missing = [
            hostname for hostname in self.known_ads
            if not is_blocked(hostname, self.blocks, self.exceptions, self.bare_blocks)
        ]
        self.assertFalse(
            missing,
            f"{len(missing)} known ad hostname(s) no longer blocked: {missing}",
        )

    def test_evidence_corpus_expected_policy_matches_subscription(self) -> None:
        mismatches = []
        for record in self.evidence_corpus["records"]:
            hostname = record["hostname"]
            policy = record["expected_policy"]
            if policy == "blocked" and not is_blocked(hostname, self.blocks, self.exceptions, self.bare_blocks):
                mismatches.append((hostname, policy, "not blocked"))
            elif policy == "allowed" and is_blocked(hostname, self.blocks, self.exceptions, self.bare_blocks):
                mismatches.append((hostname, policy, "blocked"))
        self.assertFalse(
            mismatches,
            f"{len(mismatches)} evidence-backed policy mismatch(es): {mismatches[:20]}",
        )
