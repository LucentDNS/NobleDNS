import tempfile
import unittest
from pathlib import Path
from tools.validate_browser_third_party_scope_audit import validate

COMMIT = "69965fa59a5d5a44531768780850d3e788fa93e1"

class BrowserThirdPartyScopeAuditTests(unittest.TestCase):
    def _run(self, rule="||example.test$third-party", source_line=1, warning="DNS blocking cannot preserve request-party context.", include_second=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            queue = root / "queue.csv"
            audit = root / "audit.csv"
            source = root / "source.txt"
            queue.write_text(
                "rule,source,source_line,priority,observed_context,evidence_type,evidence_url,interpretation,decision_status\n"
                "||example.test,adguard_dns,1,medium,context,upstream,https://example.test,evidence,unresolved_test_required\n",
                encoding="utf-8")
            audit.write_text(
                "hostname,browser_rule,source_line,source_commit,scope,dns_implication\n"
                f"example.test,{rule},{source_line},{COMMIT},third-party,\"{warning}\"\n",
                encoding="utf-8")
            source.write_text("||example.test$third-party\n||other.test$third-party\n", encoding="utf-8")
            return validate(queue, audit, source)
    def test_valid_row_and_source_line(self):
        self.assertEqual(self._run(), [])
    def test_wrong_scope_rule_fails(self):
        self.assertTrue(any("not the exact third-party browser rule" in e for e in self._run("||example.test")))
    def test_missing_scope_warning_fails(self):
        self.assertTrue(any("DNS scope-loss warning missing" in e for e in self._run(warning="Evidence only.")))
    def test_audit_must_cover_all_third_party_rules_in_source(self):
        self.assertTrue(any("audit is missing source-scoped hostnames: other.test" in e for e in self._run(include_second=True)))
    def test_wrong_source_line_fails(self):
        self.assertTrue(any("does not contain the exact rule" in e for e in self._run(source_line=2)))
if __name__ == "__main__":
    unittest.main()
