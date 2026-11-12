import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tools.validate_evidence_corpus import validate_corpus

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
VALID = {
    "hostname": "ads.example.com",
    "classification": "confirmed_ad",
    "evidence_type": "controlled_traffic_capture",
    "evidence_reference": "https://example.org/evidence/controlled-capture",
    "observed_at_utc": "2026-11-10T10:00:00Z",
    "reviewed_at_utc": "2026-11-11T10:00:00Z",
    "review_due_utc": "2026-12-11T10:00:00Z",
    "confidence": "high",
    "service": "Synthetic test service",
    "affected_function": "Ad delivery",
    "source_rule_refs": [],
    "source_snapshot_sha256": [],
    "expected_policy": "blocked",
    "review_notes": "Synthetic validator fixture only; not a real hostname assertion.",
}


class EvidenceCorpusTests(unittest.TestCase):
    def corpus(self, records=None):
        return {"schema_version": 1, "records": records or []}

    def test_empty_public_corpus_is_valid(self):
        path = Path(__file__).parent / "fixtures" / "evidence-corpus.json"
        self.assertEqual(validate_corpus(json.loads(path.read_text(encoding="utf-8")), NOW), [])

    def test_valid_synthetic_record(self):
        self.assertEqual(validate_corpus(self.corpus([VALID]), NOW), [])

    def test_duplicate_hostname_is_rejected(self):
        self.assertTrue(any("duplicates" in e for e in validate_corpus(self.corpus([VALID, VALID]), NOW)))

    def test_malformed_hostname_is_rejected(self):
        record = copy.deepcopy(VALID)
        record["hostname"] = "*.example.com"
        self.assertTrue(any("hostname is invalid" in e for e in validate_corpus(self.corpus([record]), NOW)))

    def test_noncanonical_uppercase_hostname_is_rejected(self):
        record = copy.deepcopy(VALID)
        record["hostname"] = "Ads.example.com"
        self.assertTrue(any("lowercase FQDN" in e for e in validate_corpus(self.corpus([record]), NOW)))

    def test_non_string_enum_values_fail_closed_without_crashing(self):
        record = copy.deepcopy(VALID)
        record["classification"] = []
        record["evidence_type"] = {}
        record["expected_policy"] = ["blocked"]
        record["confidence"] = None
        errors = validate_corpus(self.corpus([record]), NOW)
        self.assertTrue(any("classification is not an allowed" in e for e in errors))
        self.assertTrue(any("evidence_type is not an allowed" in e for e in errors))
        self.assertTrue(any("expected_policy is not an allowed" in e for e in errors))
        self.assertTrue(any("confidence is not an allowed" in e for e in errors))

    def test_unknown_and_missing_fields_are_rejected(self):
        record = copy.deepcopy(VALID)
        del record["review_notes"]
        record["comment"] = "unreviewed field"
        errors = validate_corpus(self.corpus([record]), NOW)
        self.assertTrue(any("missing fields" in e for e in errors))
        self.assertTrue(any("unknown fields" in e for e in errors))

    def test_unresolved_record_cannot_be_expected_blocked(self):
        record = copy.deepcopy(VALID)
        record["classification"] = "unresolved"
        errors = validate_corpus(self.corpus([record]), NOW)
        self.assertTrue(any("unresolved records must use observe_only" in e for e in errors))

    def test_upstream_list_alone_cannot_confirm_an_ad(self):
        record = copy.deepcopy(VALID)
        record["evidence_type"] = "upstream_rule"
        errors = validate_corpus(self.corpus([record]), NOW)
        self.assertTrue(any("confirmed_ad requires" in e for e in errors))
        self.assertTrue(any("upstream_rule evidence alone" in e for e in errors))

    def test_confirmed_ad_requires_high_confidence(self):
        record = copy.deepcopy(VALID)
        record["confidence"] = "medium"
        self.assertTrue(any("confirmed_ad requires" in e for e in validate_corpus(self.corpus([record]), NOW)))

    def test_threat_requires_expiry_and_threat_intelligence(self):
        record = copy.deepcopy(VALID)
        record.update(classification="threat", evidence_type="threat_intelligence")
        self.assertTrue(any("require expires_at_utc" in e for e in validate_corpus(self.corpus([record]), NOW)))
        record["expires_at_utc"] = "2026-11-20T00:00:00Z"
        self.assertEqual(validate_corpus(self.corpus([record]), NOW), [])

    def test_expired_threat_is_rejected(self):
        record = copy.deepcopy(VALID)
        record.update(
            classification="threat",
            evidence_type="threat_intelligence",
            expires_at_utc="2026-11-11T00:00:00Z",
        )
        self.assertTrue(any("evidence has expired" in e for e in validate_corpus(self.corpus([record]), NOW)))

    def test_overdue_review_is_rejected(self):
        record = copy.deepcopy(VALID)
        record["review_due_utc"] = "2026-11-11T00:00:00Z"
        self.assertTrue(any("review is overdue" in e for e in validate_corpus(self.corpus([record]), NOW)))

    def test_review_dates_must_be_ordered(self):
        record = copy.deepcopy(VALID)
        record["reviewed_at_utc"] = "2026-11-09T00:00:00Z"
        self.assertTrue(any("must not precede observed_at_utc" in e for e in validate_corpus(self.corpus([record]), NOW)))

    def test_source_references_require_a_snapshot_hash(self):
        record = copy.deepcopy(VALID)
        record["source_rule_refs"] = ["OISD Big:line 123"]
        self.assertTrue(any("no source snapshot hash" in e for e in validate_corpus(self.corpus([record]), NOW)))

    def test_malformed_snapshot_hash_is_rejected(self):
        record = copy.deepcopy(VALID)
        record["source_snapshot_sha256"] = ["not-a-hash"]
        self.assertTrue(any("SHA-256 hashes" in e for e in validate_corpus(self.corpus([record]), NOW)))

    def test_invalid_timestamp_is_rejected(self):
        record = copy.deepcopy(VALID)
        record["observed_at_utc"] = "2026-11-10"
        self.assertTrue(any("ISO-8601 UTC timestamp" in e for e in validate_corpus(self.corpus([record]), NOW)))


if __name__ == "__main__":
    unittest.main()
