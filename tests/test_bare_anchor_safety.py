from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "nobledns_bare_anchor_safety", ROOT / "tools" / "audit_bare_anchor_safety.py"
)
audit_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_module)


class BareAnchorSafetyTests(unittest.TestCase):
    def test_bare_anchor_matches_domain_subdomains_and_unbounded_suffix(self) -> None:
        self.assertTrue(audit_module.matches_bare_anchor("example.com", "example.com"))
        self.assertTrue(audit_module.matches_bare_anchor("api.example.com", "example.com"))
        self.assertTrue(audit_module.matches_bare_anchor("example.com.attacker.test", "example.com"))

    def test_bare_anchor_does_not_match_mid_label_prefix(self) -> None:
        self.assertFalse(audit_module.matches_bare_anchor("notexample.com", "example.com"))
        self.assertFalse(audit_module.matches_bare_anchor("fooexample.com", "example.com"))

    def test_current_bare_anchors_do_not_hit_essential_sentinels(self) -> None:
        rows = audit_module.audit(
            ROOT / "dist" / "dns-filter.txt",
            ROOT / "dist" / "sources" / "adguard_dns.txt",
            ROOT / "tests" / "fixtures" / "essential-domains.txt",
        )
        self.assertEqual(len(rows), 69)
        self.assertEqual(
            sum(int(row["essential_match_count"]) for row in rows),
            0,
        )
        self.assertTrue(all(row["source"] == "adguard_dns" for row in rows))


if __name__ == "__main__":
    unittest.main()
