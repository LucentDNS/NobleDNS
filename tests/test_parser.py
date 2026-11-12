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
            mod.FILTER_HEADER.splitlines(),
            [
                "! Title: NobleDNS Filter",
                "! Description: DNS filtering for ads, trackers, telemetry and unwanted domains.",
                "! Homepage: https://github.com/LucentDNS/NobleDNS",
                "! Sources: AdGuard DNS Filter, HaGeZi Multi Normal",
            ],
        )

    def test_syntax_audit_classifies_without_rewriting(self):
        rules = {
            "||ads.example.com^",
            "||bare.example.com",
            ".sub.example.com^",
            ".bare.example.com",
        }
        summary, review = mod.syntax_audit(
            rules,
            {
                "adguard_dns": {".sub.example.com^", "||ads.example.com^"},
                "hagezi_normal": {"||bare.example.com", ".bare.example.com"},
            },
        )
        self.assertEqual(summary["total"], 4)
        self.assertEqual(
            summary["forms"],
            {
                "anchored_domain_with_separator": 1,
                "anchored_domain_without_separator": 1,
                "leading_dot_with_separator": 1,
                "leading_dot_without_separator": 1,
            },
        )
        self.assertEqual(
            {row[0] for row in review},
            {".sub.example.com^", ".bare.example.com", "||bare.example.com"},
        )

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


    def test_leading_dot_caret_preserved(self):
        blocks, _, rejected, _ = self.parse(".ads.example.com^\n")
        self.assertEqual(blocks, {".ads.example.com^"})
        self.assertEqual(sum(rejected.values()), 0)

    def test_leading_dot_bare_preserved(self):
        blocks, _, rejected, _ = self.parse(".ads.example.com\n")
        self.assertEqual(blocks, {".ads.example.com"})
        self.assertEqual(sum(rejected.values()), 0)

    def test_leading_dot_rules_mixed(self):
        blocks, _, rejected, _ = self.parse(
            ".a.example.com^\n"
            ".b.example.com\n"
            "||c.example.com^\n"
        )
        self.assertEqual(
            blocks,
            {
                ".a.example.com^",
                ".b.example.com",
                "||c.example.com^",
            },
        )
        self.assertEqual(sum(rejected.values()), 0)

    def test_leading_dot_trailing_dot_rejected(self):
        blocks, _, rejected, rows = self.parse(
            ".1080.x.90.\n"
            "||ok.example.com^\n"
        )
        self.assertEqual(blocks, {"||ok.example.com^"})
        self.assertEqual(
            rejected["invalid_domain_length_or_trailing_dot"], 1
        )
        self.assertTrue(
            any(row[3] == ".1080.x.90." for row in rows)
        )

    def test_leading_dot_wildcard_rejected(self):
        blocks, _, rejected, _ = self.parse(
            ".*.example.com^\n"
            "||ok.example.com^\n"
        )
        self.assertEqual(blocks, {"||ok.example.com^"})
        self.assertEqual(rejected["wildcard_syntax"], 1)

    def test_real_upstream_leading_dot_fixture(self):
        fixture = Path(__file__).parent / "fixtures" / "leading-dot-rules.txt"
        raw = fixture.read_bytes()
        rules = raw.decode("utf-8").splitlines()

        self.assertEqual(len(rules), 28)
        self.assertEqual(len(set(rules)), 28)

        caret = [rule for rule in rules if rule.endswith("^")]
        bare = [
            rule for rule in rules
            if not rule.endswith("^") and not rule.endswith(".")
        ]
        trailing = [rule for rule in rules if rule.endswith(".")]

        self.assertEqual(len(caret), 23)
        self.assertEqual(len(bare), 4)
        self.assertEqual(len(trailing), 1)
        self.assertEqual(trailing, [".1080.x.90."])

        blocks, exceptions, rejected, rows = mod.parse_source(
            raw, "adguard_dns", min_blocks=1
        )

        expected = {rule for rule in rules if not rule.endswith(".")}

        self.assertEqual(blocks, expected)
        self.assertEqual(len(blocks), 27)
        self.assertEqual(exceptions, set())
        self.assertEqual(
            dict(rejected),
            {"invalid_domain_length_or_trailing_dot": 1},
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][3], ".1080.x.90.")
if __name__ == "__main__": unittest.main()
