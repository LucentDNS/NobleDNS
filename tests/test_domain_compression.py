import tempfile
import unittest
from pathlib import Path

from tools.domain_compression import (
    PSL_COMMIT,
    PSL_SHA256,
    PublicSuffixList,
    compress_simple_domain_rules,
)


class PublicSuffixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.psl = PublicSuffixList()

    def test_pinned_snapshot_and_version(self):
        self.assertEqual(PSL_COMMIT, "c3a53eed2cc49353c5fb5c30536186795d5c451b")
        self.assertEqual(self.psl.sha256, PSL_SHA256)

    def test_exact_suffixes_are_not_compression_parents(self):
        self.assertTrue(self.psl.is_public_suffix("com"))
        self.assertTrue(self.psl.is_public_suffix("co.uk"))
        self.assertFalse(self.psl.is_public_suffix("example.co.uk"))

    def test_wildcard_and_exception_rules(self):
        self.assertTrue(self.psl.is_public_suffix("a.ck"))
        self.assertFalse(self.psl.is_public_suffix("www.ck"))
        self.assertEqual(self.psl.public_suffix("www.ck"), "ck")

    def test_private_section_is_included(self):
        self.assertTrue(self.psl.is_public_suffix("blogspot.com"))
        self.assertFalse(self.psl.is_public_suffix("example.blogspot.com"))

    def test_tampered_snapshot_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suffixes.dat"
            path.write_text("com\nco.uk\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                PublicSuffixList(path)


class CompressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.psl = PublicSuffixList()

    def test_only_simple_child_rules_are_compressed(self):
        rules = {
            "||example.com^",
            "||ads.example.com^",
            "||deep.ads.example.com^",
            "||bare.example.com",
            "||*.wild.example.com^",
            "||priority.example.com^$important",
            "@@||allow.example.com^",
        }
        sources = {
            "core": {"||example.com^", "||ads.example.com^", "||bare.example.com"},
            "threat": {"||deep.ads.example.com^", "||*.wild.example.com^"},
            "other": {"||priority.example.com^$important", "@@||allow.example.com^"},
        }
        kept, audit = compress_simple_domain_rules(rules, sources, self.psl)
        self.assertEqual(kept, {
            "||example.com^",
            "||bare.example.com",
            "||*.wild.example.com^",
            "||priority.example.com^$important",
            "@@||allow.example.com^",
        })
        self.assertEqual(
            [(row["removed_rule"], row["covered_by"]) for row in audit],
            [("||ads.example.com^", "||example.com^"),
             ("||deep.ads.example.com^", "||ads.example.com^")],
        )

    def test_public_suffix_never_becomes_compression_parent(self):
        rules = {"||co.uk^", "||shop.co.uk^", "||a.shop.co.uk^"}
        kept, audit = compress_simple_domain_rules(rules, {"x": rules}, self.psl)
        self.assertEqual(kept, {"||co.uk^", "||shop.co.uk^"})
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["covered_by"], "||shop.co.uk^")

    def test_idempotent(self):
        rules = {"||example.com^", "||ads.example.com^"}
        once, _ = compress_simple_domain_rules(rules, {"x": rules}, self.psl)
        twice, audit = compress_simple_domain_rules(once, {"x": once}, self.psl)
        self.assertEqual(once, twice)
        self.assertEqual(audit, [])


if __name__ == "__main__":
    unittest.main()
