from __future__ import annotations

import csv
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "nobledns_bare_anchor_discovery_overlap",
    ROOT / "tools" / "audit_bare_anchor_discovery_overlap.py",
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class BareAnchorDiscoveryOverlapTests(unittest.TestCase):
    def test_matcher_preserves_bare_anchor_semantics(self):
        self.assertTrue(module.matches_bare_anchor("example.test", "example.test"))
        self.assertTrue(module.matches_bare_anchor("example.test.evil.test", "example.test"))
        self.assertTrue(module.matches_bare_anchor("sub.example.test", "example.test"))
        self.assertFalse(module.matches_bare_anchor("notexample.test", "example.test"))

    def test_audit_reports_overlaps_without_treating_seed_as_ground_truth(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.csv"
            discovery = Path(tmp) / "discovery.csv"
            audit.write_text(
                "rule,source,source_line_numbers,essential_match_count,essential_matches,review_status,interpretation\n"
                "||example.test,adguard_dns,42,0,,manual_hostname_review_required,No sentinel hit\n",
                encoding="utf-8",
            )
            discovery.write_text(
                "request_domain,pages_seen_on\n"
                "example.test.evil.test,1\n"
                "safe.example.org,1\n",
                encoding="utf-8",
            )
            rows = module.audit(audit, discovery)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["discovery_match_count"], "1")
        self.assertEqual(rows[0]["discovery_matches"], "example.test.evil.test")
        self.assertEqual(rows[0]["review_status"], "discovery_overlap_review_required")
        self.assertIn("not proof", rows[0]["interpretation"] if rows[0]["discovery_match_count"] == "0" else "not proof")

    def test_no_overlap_is_diagnostic_not_clearance(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.csv"
            discovery = Path(tmp) / "discovery.csv"
            audit.write_text(
                "rule,source,source_line_numbers,essential_match_count,essential_matches,review_status,interpretation\n"
                "||example.test,adguard_dns,42,0,,manual_hostname_review_required,No sentinel hit\n",
                encoding="utf-8",
            )
            discovery.write_text("request_domain\nother.test\n", encoding="utf-8")
            rows = module.audit(audit, discovery)
        self.assertEqual(rows[0]["discovery_match_count"], "0")
        self.assertIn("not proof", rows[0]["interpretation"])


if __name__ == "__main__":
    unittest.main()
