import json
import tempfile
import unittest
from pathlib import Path

from tools.audit_adguard_chinese import audit, classify, covered_by_current, load_current_rules


class AdGuardChineseAuditTests(unittest.TestCase):
    def test_classification_keeps_contextual_and_page_rules_out_of_dns_candidates(self):
        self.assertEqual(classify("||ad.example^"), "domain_hostname_pattern")
        self.assertEqual(classify("||ad.example^$third-party"), "domain_with_modifier")
        self.assertEqual(classify("||ad.example^$domain=site.example"), "domain_with_modifier")
        self.assertEqual(classify("example.com##.ad"), "cosmetic_or_element")
        self.assertEqual(classify("@@||login.example^"), "exception")
        self.assertEqual(classify("||cdn.example^*"), "domain_wildcard")

    def test_suffix_coverage_is_detected_without_approving_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.txt"
            current = root / "current.txt"
            out_csv = root / "audit.csv"
            out_json = root / "audit.json"
            source.write_text(
                "! sample\n||ads.example.com^\n||tracker.other.test^\n"
                "||third.example.com^$third-party\nsite.example##.ad\n"
                "@@||allowed.example^\n",
                encoding="utf-8",
            )
            current.write_text("! current\n||example.com^\n", encoding="utf-8")
            report = audit(source, current, out_csv, out_json)
            self.assertEqual(report["candidate_count"], 2)
            self.assertEqual(report["candidate_coverage_count"], 1)
            self.assertEqual(report["candidate_not_covered_count"], 1)
            self.assertEqual(report["classification_counts"]["domain_hostname_pattern"], 2)
            rows = out_csv.read_text(encoding="utf-8")
            self.assertIn("audit_only_not_approved_for_inclusion", rows)
            saved = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(saved["status"], "AUDIT_ONLY_NO_SOURCE_INTEGRATION")
            self.assertEqual(saved["classification_counts"]["domain_with_modifier"], 1)

    def test_invalid_ip_and_single_label_are_not_candidates(self):
        self.assertFalse(__import__("tools.audit_adguard_chinese", fromlist=["valid_hostname"]).valid_hostname("127.0.0.1"))
        self.assertFalse(__import__("tools.audit_adguard_chinese", fromlist=["valid_hostname"]).valid_hostname("localhost"))


if __name__ == "__main__":
    unittest.main()
