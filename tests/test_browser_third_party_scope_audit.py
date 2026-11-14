import tempfile
import unittest
from pathlib import Path
from tools.validate_browser_third_party_scope_audit import validate

COMMIT = "69965fa59a5d5a44531768780850d3e788fa93e1"

class BrowserThirdPartyScopeAuditTests(unittest.TestCase):
    def _run(self, rule="||example.test$third-party", warning="DNS blocking cannot preserve request-party context."):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            queue = root / "queue.csv"
            audit = root / "audit.csv"
            queue.write_text(
                "rule,source,source_line,priority,observed_context,evidence_type,evidence_url,interpretation,decision_status\n"
                "||example.test,adguard_dns,1,medium,context,upstream,https://example.test,evidence,unresolved_test_required\n",
                encoding="utf-8")
            audit.write_text(
                "hostname,browser_rule,source_line,source_commit,scope,dns_implication\n"
                f"example.test,{rule},42,{COMMIT},third-party,\"{warning}\"\n",
                encoding="utf-8")
            return validate(queue, audit)
    def test_valid_row(self):
        self.assertEqual(self._run(), [])
    def test_wrong_scope_rule_fails(self):
        self.assertTrue(any("not the exact third-party browser rule" in e for e in self._run("||example.test")))
    def test_missing_scope_warning_fails(self):
        self.assertTrue(any("DNS scope-loss warning missing" in e for e in self._run(warning="Evidence only.")))
if __name__ == "__main__":
    unittest.main()
