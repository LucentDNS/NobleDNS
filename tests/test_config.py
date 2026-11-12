import importlib.util
import json
import re
import tempfile
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("nobledns_update", Path(__file__).parents[1] / "update.py")
mod = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class ConfigTests(unittest.TestCase):
    def test_filter_header_has_version_and_expiry_metadata(self):
        header = mod.filter_header("1.2.3")
        self.assertTrue(header.startswith("! Title: NobleDNS Filter\\n"))
        self.assertIn("! Homepage: https://github.com/LucentDNS/NobleDNS\\n", header)
        self.assertIn("! Version: 1.2.3\\n", header)
        self.assertIn("! Expires: 1 day\\n", header)

    def test_project_version_is_stable_semver(self):
        self.assertRegex(mod.VERSION_BASE, r"^\\d+\\.\\d+\\.\\d+$")

    def test_exactly_two_approved_sources(self):
        cfg = mod.load_config()
        self.assertEqual([x["key"] for x in cfg["sources"]], ["adguard_dns", "hagezi_normal"])
        self.assertEqual(cfg["max_rules"], 500000)

    def test_drift_gate_blocks_large_source_change(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "manifest.json"
            p.write_text(json.dumps({"sources": {"adguard_dns": {"simple_block_rules": 100}}}))
            with self.assertRaises(RuntimeError):
                mod.check_drift({"adguard_dns": {"simple_block_rules": 130}}, set(), p, 15.0)

    def test_drift_gate_blocks_large_rule_set_delta(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "manifest.json"
            p.write_text(json.dumps({"sources": {}}))
            (Path(td) / "dns-filter.txt").write_text("! old\\n" + "\\n".join(f"||d{i}.example.com^" for i in range(100)))
            current = {f"||d{i}.example.com^" for i in range(90)} | {f"||new{i}.example.net^" for i in range(30)}
            with self.assertRaises(RuntimeError):
                mod.check_drift({}, current, p, 15.0)


if __name__ == "__main__":
    unittest.main()
