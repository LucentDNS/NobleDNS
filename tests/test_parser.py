import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("nobledns_update", Path(__file__).parents[1] / "update.py")
mod = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class ParserTests(unittest.TestCase):
    def parse(self, text):
        return mod.parse_source(text.encode("utf-8"), "test", min_blocks=1)

    def test_filter_metadata_header(self):
        self.assertEqual(
            mod.filter_header("1.0.0").splitlines(),
            [
                "! Title: NobleDNS Filter",
                "! Description: Balanced DNS filtering for ads, trackers and unwanted domains.",
                "! Homepage: https://github.com/LucentDNS/NobleDNS",
                "! Version: 1.0.0",
                "! Expires: 1 day",
                "! Sources: AdGuard DNS Filter, HaGeZi Multi Normal",
            ],
        )

    def test_syntax_audit_uses_documented_dns_semantics(self):
        rules = {
            "||ads.example.com^",
            "||bare.example.com",
        }
        summary, review = mod.syntax_audit(
            rules,
            {
                "adguard_dns": {".sub.example.com^", "||ads.example.com^"},
                "hagezi_normal": {"||bare.example.com", ".bare.example.com"},
            },
        )
        self.assertEqual(summary["total"], 2)
        self.assertEqual(
            summary["forms"],
            {
                "domain_and_subdomains": 1,
                "domain_anchor_without_end_boundary": 1,
            },
        )
        self.assertEqual(summary["review_required"], 1)
        self.assertEqual(len(review), 1)
        self.assertEqual(review[0][0], "||bare.example.com")
        self.assertEqual(summary["forms"]["domain_anchor_without_end_boundary"], 1)

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

    def test_valid_idna2008_punycode_is_kept(self):
        blocks, _, rejected, _ = self.parse("||xn--fufrieden-h1a.de^\n")
        self.assertIn("||xn--fufrieden-h1a.de^", blocks)
        self.assertEqual(rejected["invalid_punycode_label"], 0)

    def test_invalid_alabel_is_rejected(self):
        blocks, _, rejected, _ = self.parse(
            "||xn--abc.example.com^\n||ok.example.com^\n"
        )
        self.assertEqual(blocks, {"||ok.example.com^"})
        self.assertEqual(rejected["invalid_punycode_label"], 1)

    def test_ascii_domain_is_unchanged(self):
        blocks, _, _, _ = self.parse("||ads.example.com^\n")
        self.assertEqual(blocks, {"||ads.example.com^"})


    def test_leading_dot_rules_are_rejected(self):
        blocks, _, rejected, rows = self.parse(
            ".ads.example.com^\n"
            ".bare.example.com\n"
            "||ok.example.com^\n"
        )
        self.assertEqual(blocks, {"||ok.example.com^"})
        self.assertEqual(rejected["unsupported_leading_dot_dns_syntax"], 2)
        self.assertEqual([row[3] for row in rows], [".ads.example.com^", ".bare.example.com"])

    def test_real_upstream_leading_dot_fixture_is_fully_excluded(self):
        fixture = Path(__file__).parent / "fixtures" / "leading-dot-rules.txt"
        raw = fixture.read_bytes()
        rules = raw.decode("utf-8").splitlines()
        self.assertEqual(len(rules), 28)
        self.assertEqual(len(set(rules)), 28)

        blocks, exceptions, rejected, rows = mod.parse_source(
            raw, "adguard_dns", min_blocks=0
        )
        self.assertEqual(blocks, set())
        self.assertEqual(exceptions, set())
        self.assertEqual(rejected["unsupported_leading_dot_dns_syntax"], 28)
        self.assertEqual(len(rows), 28)
if __name__ == "__main__": unittest.main()
