import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("nobledns_update", Path(__file__).parents[1] / "update.py")
mod = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class AllowlistTests(unittest.TestCase):
    def test_empty_project_allowlist_is_valid(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "allowlist.txt"
            path.write_text("# reviewed exact hostnames only\n", encoding="utf-8")
            self.assertEqual(mod.parse_allowlist(path), set())

    def test_allowlist_generates_active_exception_and_removes_matching_subtree(self):
        blocks = {
            "||example.com^",
            "||ads.example.com^",
            "||unrelated.net^",
        }
        kept, exceptions = mod.apply_allowlist(blocks, {"example.com"})
        self.assertEqual(kept, {"||unrelated.net^"})
        self.assertEqual(exceptions, {"@@||example.com^"})

    def test_allowlist_is_case_normalized_and_rejects_duplicate(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "allowlist.txt"
            path.write_text("Example.com\nexample.com\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate allowlist"):
                mod.parse_allowlist(path)

    def test_allowlist_rejects_rule_syntax_and_broad_patterns(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "allowlist.txt"
            path.write_text("||example.com^\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exact domain"):
                mod.parse_allowlist(path)

    def test_proxy_validation_rejects_credentials_and_unsupported_schemes(self):
        with self.assertRaisesRegex(ValueError, "credentials"):
            mod.validate_proxy("http://user:pass@127.0.0.1:7890")
        with self.assertRaisesRegex(ValueError, "http:// or https://"):
            mod.validate_proxy("socks5://127.0.0.1:1080")

    def test_proxy_validation_accepts_http_endpoint(self):
        self.assertEqual(mod.validate_proxy("http://127.0.0.1:7890"), "http://127.0.0.1:7890")


if __name__ == "__main__":
    unittest.main()
