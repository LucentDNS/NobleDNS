from __future__ import annotations

import csv
import importlib.util
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("nobledns_benchmark_scorer", ROOT / "tools" / "score_benchmark.py")
scorer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scorer)


class BenchmarkScorerTests(unittest.TestCase):
    def test_parent_block_and_exception_precedence(self) -> None:
        blocks = {"||ads.example.test^", "||example.test^"}
        exceptions = {"@@||safe.example.test^"}
        self.assertEqual(scorer.decide("cdn.ads.example.test", blocks, exceptions)[0], "block")
        self.assertEqual(scorer.decide("safe.example.test", blocks, exceptions)[0], "allow")
        self.assertEqual(scorer.decide("child.safe.example.test", blocks, exceptions)[0], "allow")
        self.assertEqual(scorer.decide("notexample.test", blocks, exceptions)[0], "allow")

    def test_bare_anchor_has_no_hostname_end_separator(self) -> None:
        blocks = {"||example.test"}
        self.assertEqual(scorer.decide("example.test.evil.test", blocks, set())[0], "block")
        self.assertEqual(scorer.decide("www.example.test.evil.test", blocks, set())[0], "block")
        self.assertEqual(scorer.decide("notexample.test", blocks, set())[0], "allow")
        caret = {"||example.test^"}
        self.assertEqual(scorer.decide("example.test.evil.test", caret, set())[0], "allow")
        self.assertEqual(scorer.decide("www.example.test", caret, set())[0], "block")

    def test_undocumented_leading_dot_syntax_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.txt"
            path.write_text("||valid.example.test^\n.example.test^\n", encoding="utf-8")
            blocks, exceptions, unsupported = scorer.load_rules(path)
            self.assertEqual(blocks, {"||valid.example.test^"})
            self.assertEqual(exceptions, set())
            self.assertEqual(len(unsupported), 1)
            self.assertIn(".example.test^", unsupported[0])

    def test_rule_loader_rejects_trailing_dot_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.txt"
            path.write_text("||valid.example.test^\n||invalid.example.test.^\n", encoding="utf-8")
            blocks, exceptions, unsupported = scorer.load_rules(path)
            self.assertEqual(blocks, {"||valid.example.test^"})
            self.assertEqual(exceptions, set())
            self.assertEqual(len(unsupported), 1)
            self.assertIn("invalid hostname", unsupported[0])

    def test_confusion_matrix_is_category_specific(self) -> None:
        rows = [
            {"hostname": "ads.example.test", "category": "ad", "expected": "block", "evidence_ref": "test-1"},
            {"hostname": "safe.example.test", "category": "essential", "expected": "allow", "evidence_ref": "test-2"},
            {"hostname": "miss.example.test", "category": "tracking", "expected": "block", "evidence_ref": "test-3"},
        ]
        result = scorer.score(rows, {"||ads.example.test^"}, set())
        self.assertEqual(result["by_category"]["ad"]["tp"], 1)
        self.assertEqual(result["by_category"]["essential"]["tn"], 1)
        self.assertEqual(result["by_category"]["tracking"]["fn"], 1)

    def test_empty_or_unsupported_corpus_records_are_not_silently_scored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=scorer.FIELDS)
                writer.writeheader()
                writer.writerow({
                    "hostname": "ads.example.test", "category": "ad", "expected": "block",
                    "evidence_ref": "test-evidence", "evidence_summary": "controlled test evidence",
                    "confidence": "high", "reviewed_on": "2026-11-01", "expires_on": "",
                    "independent": "true", "reviewer": "reviewer-a",
                })
            rows, errors = scorer.load_corpus(path, date(2026, 11, 12))
            self.assertEqual(errors, [])
            self.assertEqual(len(rows), 1)


    def test_category_policy_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=scorer.FIELDS)
                writer.writeheader()
                writer.writerow({
                    "hostname": "ads.example.test", "category": "ad", "expected": "allow",
                    "evidence_ref": "test-evidence", "evidence_summary": "reviewed evidence",
                    "confidence": "high", "reviewed_on": "2026-11-01", "expires_on": "",
                    "independent": "true", "reviewer": "reviewer-a",
                })
            rows, errors = scorer.load_corpus(path, date(2026, 11, 12))
            self.assertEqual(rows, [])
            self.assertTrue(any("requires expected=block" in error for error in errors))

    def test_essential_category_requires_allow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=scorer.FIELDS)
                writer.writeheader()
                writer.writerow({
                    "hostname": "service.example.test", "category": "essential", "expected": "block",
                    "evidence_ref": "test-evidence", "evidence_summary": "reviewed evidence",
                    "confidence": "high", "reviewed_on": "2026-11-01", "expires_on": "",
                    "independent": "true", "reviewer": "reviewer-a",
                })
            rows, errors = scorer.load_corpus(path, date(2026, 11, 12))
            self.assertEqual(rows, [])
            self.assertTrue(any("requires expected=allow" in error for error in errors))

    def test_stale_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=scorer.FIELDS)
                writer.writeheader()
                writer.writerow({
                    "hostname": "ads.example.test", "category": "ad", "expected": "block",
                    "evidence_ref": "test-evidence", "evidence_summary": "expired evidence",
                    "confidence": "high", "reviewed_on": "2026-10-01", "expires_on": "2026-11-01",
                    "independent": "true", "reviewer": "reviewer-a",
                })
            rows, errors = scorer.load_corpus(path, date(2026, 11, 12))
            self.assertEqual(rows, [])
            self.assertTrue(any("evidence expired" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
