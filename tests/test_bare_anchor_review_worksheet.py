from __future__ import annotations

import csv
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "nobledns_review_worksheet",
    ROOT / "tools" / "validate_bare_anchor_review_worksheet.py",
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class BareAnchorReviewWorksheetTests(unittest.TestCase):
    def test_committed_worksheet_covers_current_audit(self) -> None:
        counts, errors = module.validate(
            ROOT / "dist" / "bare-anchor-audit.csv",
            ROOT / "benchmark" / "review" / "bare-anchor-review-worksheet.csv",
        )
        self.assertEqual(errors, [])
        self.assertEqual(sum(counts.values()), 69)
        self.assertEqual(counts["P0"], 4)

    def test_missing_rule_fails_inventory_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.csv"
            worksheet = Path(tmp) / "worksheet.csv"
            audit.write_text(
                "rule,source,source_line_numbers,essential_match_count,essential_matches,review_status,interpretation\n"
                "||example.test,adguard_dns,12,0,,manual_hostname_review_required,No hit\n",
                encoding="utf-8",
            )
            worksheet.write_text(
                "rule,source,source_line,review_priority,hostname_cue,classification,evidence_status,decision,reviewer,independent_reviewer,notes\n",
                encoding="utf-8",
            )
            _, errors = module.validate(audit, worksheet)
            self.assertTrue(any("missing 1 current audit rules" in error for error in errors))

    def test_duplicate_rule_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.csv"
            worksheet = Path(tmp) / "worksheet.csv"
            audit.write_text(
                "rule,source,source_line_numbers,essential_match_count,essential_matches,review_status,interpretation\n"
                "||example.test,adguard_dns,12,0,,manual_hostname_review_required,No hit\n",
                encoding="utf-8",
            )
            header = "rule,source,source_line,review_priority,hostname_cue,classification,evidence_status,decision,reviewer,independent_reviewer,notes\n"
            row = "||example.test,adguard_dns,12,P2,none,unclassified,not_reviewed,pending,,,,\n"
            worksheet.write_text(header + row + row, encoding="utf-8")
            _, errors = module.validate(audit, worksheet)
            self.assertTrue(any("duplicate worksheet rule" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
