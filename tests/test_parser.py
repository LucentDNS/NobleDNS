import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("nobledns_update", Path(__file__).parents[1] / "update.py")
mod = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class ParserTests(unittest.TestCase):
    def parse(self, text):
        return mod.parse_source(text.encode("utf-8"), "test", min_blocks=1)

    def test_caret_rule(self):
        blocks, _, _, _ = self.parse("||ads.example.com^\n")
        self.assertEqual(blocks, {"||ads.example.com^"})

    def test_bare_anchor_preserved(self):
        blocks, _, _, _ = self.parse("||ads.example.com\n")
        self.assertEqual(blocks, {"||ads.example.com"})

    def test_exception_separate(self):
        blocks, exceptions, _, _ = self.parse("||ads.example.com^\n@@||safe.example.com^\n")
        self.assertEqual(blocks, {"||ads.example.com^"})
        self.assertEqual(exceptions, {"@@||safe.example.com^"})

    def test_wildcard_excluded(self):
        blocks, _, rejected, rows = self.parse("||*.example.com^\n||ok.example.com^\n")
        self.assertEqual(blocks, {"||ok.example.com^"})
        self.assertEqual(rejected["wildcard_syntax"], 1)

    def test_trailing_dot_not_silently_normalized(self):
        blocks, _, rejected, _ = self.parse("||analytics.example.\n||ok.example.com^\n")
        self.assertEqual(blocks, {"||ok.example.com^"})
        self.assertEqual(rejected["other_anchor_syntax"], 1)

    def test_ip_and_single_label_excluded(self):
        blocks, _, rejected, _ = self.parse("||127.0.0.1^\n||localhost^\n||ok.example.com^\n")
        self.assertEqual(blocks, {"||ok.example.com^"})
        self.assertEqual(rejected["ip_literal_not_domain"], 1)
        self.assertEqual(rejected["single_label_not_fqdn"], 1)

    def test_invalid_utf8_fails_closed(self):
        with self.assertRaises(UnicodeDecodeError):
            mod.parse_source(b"\xff\xfe\xfa", "test", min_blocks=1)

    def test_ipv4_like_invalid_address_excluded(self):
        blocks, _, rejected, _ = self.parse("||999.1.1.1^\n||ok.example.com^\n")
        self.assertEqual(blocks, {"||ok.example.com^"})
        self.assertEqual(rejected["invalid_or_ip_literal"], 1)

    def test_duplicate_deduplication(self):
        blocks, _, _, _ = self.parse("||a.example.com^\n||a.example.com^\n")
        self.assertEqual(len(blocks), 1)

if __name__ == "__main__": unittest.main()
