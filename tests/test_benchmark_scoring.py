from __future__ import annotations

import csv
import hashlib
import importlib.util
import tempfile
import unittest
from unittest.mock import patch
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("nobledns_benchmark_scorer", ROOT / "tools" / "score_benchmark.py")
scorer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scorer)


class BenchmarkScorerTests(unittest.TestCase):
    def test_file_identity_records_size_and_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.txt"
            data = b"||ads.example.test^\\n"
            path.write_bytes(data)
            identity = scorer.file_identity(path)
            self.assertEqual(identity["bytes"], len(data))
            self.assertEqual(identity["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(identity["path"], str(path))

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

    def test_valid_high_confidence_corpus_record_passes_schema_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=scorer.FIELDS)
                writer.writeheader()
                writer.writerow({
                    "hostname": "ads.example.test", "category": "ad", "expected": "block",
                    "evidence_ref": "test-evidence", "evidence_summary": "controlled test evidence",
                    "confidence": "high", "reviewed_on": "2026-11-01", "expires_on": "",
                    "independent": "true", "reviewer": "reviewer-a", "independent_reviewer": "reviewer-b",
                })
            rows, errors = scorer.load_corpus(path, date(2026, 11, 12))
            self.assertEqual(errors, [])
            self.assertEqual(len(rows), 1)


    def test_cli_refuses_to_score_an_empty_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus.csv"
            rules = root / "rules.txt"
            output = root / "score.json"
            corpus.write_text(",".join(scorer.FIELDS) + "\n", encoding="utf-8")
            rules.write_text("||ads.example.test^\n", encoding="utf-8")
            with patch("sys.argv", [
                "score_benchmark.py", "--rules", str(rules), "--corpus", str(corpus),
                "--output", str(output), "--today", "2026-11-12",
            ]):
                self.assertEqual(scorer.main(), 2)
            self.assertFalse(output.exists())
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
                    "independent": "true", "reviewer": "reviewer-a", "independent_reviewer": "reviewer-b",
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
                    "independent": "true", "reviewer": "reviewer-a", "independent_reviewer": "reviewer-b",
                })
            rows, errors = scorer.load_corpus(path, date(2026, 11, 12))
            self.assertEqual(rows, [])
            self.assertTrue(any("requires expected=allow" in error for error in errors))

    def test_corpus_normalizes_one_terminal_root_dot_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=scorer.FIELDS)
                writer.writeheader()
                writer.writerow({
                    "hostname": "ads.example.test.", "category": "ad", "expected": "block",
                    "evidence_ref": "test-evidence", "evidence_summary": "reviewed evidence",
                    "confidence": "high", "reviewed_on": "2026-11-01", "expires_on": "",
                    "independent": "true", "reviewer": "reviewer-a", "independent_reviewer": "reviewer-b",
                })
                writer.writerow({
                    "hostname": "double-dot.example.test..", "category": "ad", "expected": "block",
                    "evidence_ref": "test-evidence-2", "evidence_summary": "reviewed evidence",
                    "confidence": "high", "reviewed_on": "2026-11-01", "expires_on": "",
                    "independent": "true", "reviewer": "reviewer-a", "independent_reviewer": "reviewer-b",
                })
            rows, errors = scorer.load_corpus(path, date(2026, 11, 12))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["hostname"], "ads.example.test")
            self.assertTrue(any("invalid hostname" in error for error in errors))

    def test_threat_evidence_requires_expiry_and_two_distinct_reviewers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=scorer.FIELDS)
                writer.writeheader()
                writer.writerow({
                    "hostname": "threat.example.test", "category": "threat", "expected": "block",
                    "evidence_ref": "threat-feed-1", "evidence_summary": "time-bound threat evidence",
                    "confidence": "high", "reviewed_on": "2026-11-01", "expires_on": "",
                    "independent": "true", "reviewer": "reviewer-a", "independent_reviewer": "reviewer-a",
                })
            rows, errors = scorer.load_corpus(path, date(2026, 11, 12))
            self.assertEqual(rows, [])
            self.assertTrue(any("requires an expiry date" in error for error in errors))
            self.assertTrue(any("must differ from primary reviewer" in error for error in errors))
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
                    "independent": "true", "reviewer": "reviewer-a", "independent_reviewer": "reviewer-b",
                })
            rows, errors = scorer.load_corpus(path, date(2026, 11, 12))
            self.assertEqual(rows, [])
            self.assertTrue(any("evidence expired" in error for error in errors))


class BenchmarkDiscoveryIntegrityTests(unittest.TestCase):
    def _write(self, root: Path, name: str, fields: list[str], rows: list[dict[str, str]]) -> Path:
        path = root / name
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def test_discovery_and_triage_match_without_approving_candidates(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("nobledns_discovery_validator", ROOT / "tools" / "validate_benchmark_discovery.py")
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        source_row = {"request_domain":"ads.example.com","pages_seen_on":"100","share_of_pages":"0.1","requests_total":"200","requests_setting_cookies":"50","cookie_setting_request_share":"0.25"}
        triage_row = {"domain":source_row["request_domain"],**{k:v for k,v in source_row.items() if k != "request_domain"},"owner":"Example Ads","owner_category":"ads","preliminary_lane":"adtech_candidate","evidence":"https://example.com/source","review_status":"primary_triage_only","review_note":"Not approved for blocking; domain-level review required."}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=self._write(root,"source.csv",validator.SOURCE_FIELDS,[source_row])
            triage=self._write(root,"triage.csv",validator.TRIAGE_FIELDS,[triage_row])
            counts,errors=validator.validate(source,triage)
        self.assertEqual(errors,[])
        self.assertEqual(counts["adtech_candidate"],1)

    def test_tampered_metrics_and_incorrect_lane_are_rejected(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("nobledns_discovery_validator", ROOT / "tools" / "validate_benchmark_discovery.py")
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        source_row = {"request_domain":"cdn.example.com","pages_seen_on":"100","share_of_pages":"0.1","requests_total":"200","requests_setting_cookies":"50","cookie_setting_request_share":"0.25"}
        triage_row = {"domain":source_row["request_domain"],**{k:v for k,v in source_row.items() if k != "request_domain"},"share_of_pages":"0.9","owner":"Example CDN","owner_category":"infra","preliminary_lane":"adtech_candidate","evidence":"https://example.com/source","review_status":"primary_triage_only","review_note":"Not approved for blocking."}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=self._write(root,"source.csv",validator.SOURCE_FIELDS,[source_row])
            triage=self._write(root,"triage.csv",validator.TRIAGE_FIELDS,[triage_row])
            _,errors=validator.validate(source,triage)
        self.assertTrue(any("source field changed" in e for e in errors))
        self.assertTrue(any("conflicts with owner_category" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
