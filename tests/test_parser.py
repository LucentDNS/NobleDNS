import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("nobledns_update", Path(__file__).parents[1] / "update.py")
mod = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class ParserTests(unittest.TestCase):
    def parse(self, text):
        return mod.parse_source(text.encode("utf-8"), "test", min_blocks=1)[:4]

    def test_filter_metadata_header(self):
        self.assertEqual(
            mod.FILTER_HEADER.splitlines(),
            [
                "! Title: NobleDNS Filter",
                "! Description: DNS filtering for ads, trackers, telemetry and unwanted domains.",
                "! Homepage: https://github.com/LucentDNS/NobleDNS",
                f"! Version: {mod.VERSION_BASE}",
                "! Expires: 1 day",
                "! Sources: AdGuard DNS Filter, HaGeZi Multi Normal",
                "! License: GPL-3.0-only (code); upstream rule data: GPL-3.0 (see THIRD-PARTY-NOTICES; third-party rights may apply).",
                "! Content: Listed domains are included as blocking targets only.",
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
                "adguard_dns": {"||ads.example.com^"},
                "hagezi_normal": {"||bare.example.com"},
            },
        )
        self.assertEqual(summary["total"], 2)
        self.assertEqual(
            summary["forms"],
            {
                "domain_and_subdomains": 1,
                "domain_anchor_without_end_boundary": 1,
                "subdomains_only": 0,
            },
        )
        self.assertEqual(summary["review_required"], 1)
        self.assertEqual(len(review), 1)
        self.assertEqual(review[0][0], "||bare.example.com")
        self.assertIn("hostname-start anchor", summary["semantics"]["domain_anchor_without_end_boundary"])
        self.assertIn("not the apex domain", summary["semantics"]["subdomains_only"])

    def test_caret_rule(self):
        blocks, _, _, _ = self.parse("||ads.example.com^\n")
        self.assertEqual(blocks, {"||ads.example.com^"})

    def test_bare_anchor_preserved(self):
        blocks, _, _, _ = self.parse("||ads.example.com\n")
        self.assertEqual(blocks, {"||ads.example.com"})

    def test_exception_is_rendered_as_active_allow_rule(self):
        blocks, exceptions, _, _ = self.parse("||ads.example.com^\n@@||safe.example.com^\n")
        self.assertEqual(blocks, {"||ads.example.com^"})
        self.assertEqual(exceptions, {"@@||safe.example.com^"})
        rendered = mod.render_subscription(blocks, exceptions)
        self.assertIn("@@||safe.example.com^", rendered.splitlines())
        self.assertIn("||ads.example.com^", rendered.splitlines())

    def test_complex_exception_is_not_activated(self):
        blocks, exceptions, rejected, _ = self.parse("||ads.example.com^\n@@||safe.example.com^$important\n")
        self.assertEqual(blocks, {"||ads.example.com^"})
        self.assertEqual(exceptions, set())
        self.assertEqual(rejected["modifier_important"], 1)

    def test_render_rejects_rule_in_both_sets(self):
        with self.assertRaises(ValueError):
            mod.render_subscription({"||same.example.com^"}, {"||same.example.com^"})

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


    def test_badfilter_directive_targets_exact_supported_rule(self):
        blocks, exceptions, rejected, rows, directives = mod.parse_source(
            b"||linksprf.com^\n||linksprf.com^$badfilter\n||linksprf.com\n",
            "adguard_dns",
            min_blocks=1,
        )
        self.assertEqual(blocks, {"||linksprf.com^", "||linksprf.com"})
        self.assertEqual(exceptions, set())
        self.assertEqual(rejected["modifier_badfilter"], 0)
        self.assertEqual(rows, [])
        self.assertEqual(
            directives,
            [("adguard_dns", 2, "||linksprf.com^$badfilter", "||linksprf.com^", "pending")],
        )

    def test_badfilter_unsupported_target_is_audited_and_excluded(self):
        blocks, exceptions, rejected, rows, directives = mod.parse_source(
            b"||keep.example.com^\nwykop.pl$badfilter\n",
            "adguard_dns",
            min_blocks=1,
        )
        self.assertEqual(blocks, {"||keep.example.com^"})
        self.assertEqual(exceptions, set())
        self.assertEqual(rejected["modifier_badfilter_unsupported_target"], 1)
        self.assertEqual(rows[0][3], "wykop.pl$badfilter")
        self.assertEqual(directives[0][4], "unsupported_target_syntax")

    def test_badfilter_removes_exact_target_from_merged_sources(self):
        parsed = {
            "adguard_dns": {"||linksprf.com^", "||linksprf.com", "||keep.example.com^"},
            "hagezi_normal": {"||linksprf.com^", "||other.example.com^"},
        }
        exceptions = {"adguard_dns": set(), "hagezi_normal": set()}
        directives = [
            ("adguard_dns", 8331, "||linksprf.com^$badfilter", "||linksprf.com^", "pending")
        ]
        audit = mod.apply_badfilters(parsed, exceptions, directives)
        self.assertEqual(parsed["adguard_dns"], {"||linksprf.com", "||keep.example.com^"})
        self.assertEqual(parsed["hagezi_normal"], {"||other.example.com^"})
        self.assertEqual(audit[0][4], "applied")
        self.assertEqual(audit[0][5], "adguard_dns;hagezi_normal")

    def test_badfilter_missing_target_is_recorded_without_broad_removal(self):
        parsed = {"adguard_dns": {"||keep.example.com^"}, "hagezi_normal": set()}
        exceptions = {"adguard_dns": set(), "hagezi_normal": set()}
        directives = [
            ("adguard_dns", 1, "||missing.example.test^$badfilter", "||missing.example.test^", "pending")
        ]
        audit = mod.apply_badfilters(parsed, exceptions, directives)
        self.assertEqual(parsed["adguard_dns"], {"||keep.example.com^"})
        self.assertEqual(audit[0][4], "target_not_found")

    def test_leading_dot_rules_preserve_subdomain_only_semantics(self):
        blocks, _, rejected, rows = mod.parse_source(
            b".ads.example.com^\n.bare.example.com\n||ok.example.com^\n",
            "test",
            min_blocks=1,
        )
        self.assertEqual(
            blocks,
            {".ads.example.com^", ".bare.example.com", "||ok.example.com^"},
        )
        self.assertEqual(rejected["unsupported_leading_dot_dns_syntax"], 0)
        self.assertEqual(rows, [])

    def test_syntax_audit_accepts_leading_dot_forms(self):
        summary, review = mod.syntax_audit({".ads.example.com^", ".bare.example.com"}, {})
        self.assertEqual(summary["forms"]["subdomains_only"], 2)
        self.assertEqual(summary["review_required"], 0)
        self.assertEqual(review, [])

    def test_real_upstream_leading_dot_fixture_keeps_valid_rules(self):
        fixture = Path(__file__).parent / "fixtures" / "leading-dot-rules.txt"
        raw = fixture.read_bytes()
        rules = raw.decode("utf-8").splitlines()
        self.assertEqual(len(rules), 28)
        self.assertEqual(len(set(rules)), 28)

        blocks, exceptions, rejected, rows, badfilters = mod.parse_source(
            raw, "adguard_dns", min_blocks=0
        )
        self.assertEqual(len(blocks), 27)
        self.assertEqual(exceptions, set())
        self.assertEqual(rejected["invalid_domain_length_or_trailing_dot"], 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][3], ".1080.x.90.")
        self.assertEqual(badfilters, [])

if __name__ == "__main__": unittest.main()
