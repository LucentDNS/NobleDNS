from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "nobledns_bare_anchor_evidence_queue",
    ROOT / "tools" / "validate_bare_anchor_evidence_queue.py",
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class BareAnchorEvidenceQueueTests(unittest.TestCase):
    def _write_fixtures(self, tmp: str, queue_rows: str):
        audit = Path(tmp) / "audit.csv"
        queue = Path(tmp) / "queue.csv"
        audit.write_text(
            "rule,source,source_line_numbers,essential_match_count,essential_matches,review_status,interpretation\n"
            "||example.test,adguard_dns,42,0,,manual_hostname_review_required,No sentinel hit\n",
            encoding="utf-8",
        )
        queue.write_text(
            "rule,source,source_line,priority,observed_context,evidence_type,evidence_url,interpretation,decision_status\n"
            + queue_rows,
            encoding="utf-8",
        )
        return audit, queue

    def test_valid_unresolved_record_passes(self):
        row = "||example.test,adguard_dns,42,medium,Observed context,upstream_classification,https://example.test/evidence,Evidence does not establish safety,unresolved_test_required\n"
        with tempfile.TemporaryDirectory() as tmp:
            audit, queue = self._write_fixtures(tmp, row)
            counts, errors = module.validate(audit, queue)
        self.assertEqual(errors, [])
        self.assertEqual(counts["medium"], 1)

    def test_duplicate_record_fails(self):
        row = "||example.test,adguard_dns,42,medium,Observed context,upstream_classification,https://example.test/evidence,Evidence does not establish safety,unresolved_test_required\n"
        with tempfile.TemporaryDirectory() as tmp:
            audit, queue = self._write_fixtures(tmp, row + row)
            _, errors = module.validate(audit, queue)
        self.assertTrue(any("duplicate queue rule" in error for error in errors))

    def test_floating_github_evidence_ref_fails(self):
        urls = (
            "https://github.com/example/repo/blob/master/list.txt",
            "https://raw.githubusercontent.com/example/repo/main/list.txt",
        )
        for url in urls:
            with self.subTest(url=url):
                row = f"||example.test,adguard_dns,42,medium,Observed context,upstream_classification,{url},Evidence does not establish safety,unresolved_test_required\\n"
                with tempfile.TemporaryDirectory() as tmp:
                    audit, queue = self._write_fixtures(tmp, row)
                    _, errors = module.validate(audit, queue)
                self.assertTrue(any("immutable commit refs" in error for error in errors))

    def test_wrong_source_line_fails(self):
        row = "||example.test,adguard_dns,999,medium,Observed context,upstream_classification,https://example.test/evidence,Evidence does not establish safety,unresolved_test_required\n"
        with tempfile.TemporaryDirectory() as tmp:
            audit, queue = self._write_fixtures(tmp, row)
            _, errors = module.validate(audit, queue)
        self.assertTrue(any("source line mismatch" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
