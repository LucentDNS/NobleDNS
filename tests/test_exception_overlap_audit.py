from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "nobledns_exception_overlap_audit", ROOT / "tools" / "audit_exception_overlaps.py"
)
audit_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_module)


class ExceptionOverlapAuditTests(unittest.TestCase):
    def test_parent_block_overlaps_child_exception(self) -> None:
        self.assertEqual(
            audit_module.overlap_relation("api.ads.tvb.com", "ads.tvb.com", True),
            "exception_below_block",
        )

    def test_parent_exception_overlaps_child_block_and_is_high_priority(self) -> None:
        self.assertEqual(
            audit_module.overlap_relation("ad.10010.com", "m1.ad.10010.com", True),
            "block_below_exception",
        )

    def test_unrelated_domains_do_not_overlap(self) -> None:
        self.assertIsNone(
            audit_module.overlap_relation("captcha.su.baidu.com", "ads.tvb.com", True)
        )

    def test_bare_anchor_is_reported_as_potential_not_proven_overlap(self) -> None:
        self.assertEqual(
            audit_module.overlap_relation("ads.example.com", "ads.example.com", False),
            "bare_anchor_same_domain",
        )

    def test_audit_reports_only_actual_scope_intersections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.txt"
            rules.write_text(
                "||ads.tvb.com^\n"
                "||m1.ad.10010.com^\n"
                "@@||api.ads.tvb.com^\n"
                "@@||ad.10010.com^\n"
                "@@||captcha.su.baidu.com^\n",
                encoding="utf-8",
            )
            rows = audit_module.audit(rules)
        by_rule = {row["exception_rule"]: row for row in rows}
        tvb = by_rule["@@||api.ads.tvb.com^"]
        unicom = by_rule["@@||ad.10010.com^"]
        baidu = by_rule["@@||captcha.su.baidu.com^"]
        self.assertEqual(tvb["overlap_count"], "1")
        self.assertEqual(tvb["review_priority"], "medium")
        self.assertEqual(unicom["overlap_count"], "1")
        self.assertEqual(unicom["review_priority"], "high")
        self.assertEqual(baidu["overlap_count"], "0")
        self.assertEqual(baidu["review_priority"], "none")


if __name__ == "__main__":
    unittest.main()
