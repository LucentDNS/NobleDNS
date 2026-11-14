import importlib.util
from pathlib import Path
import unittest
SPEC = importlib.util.spec_from_file_location("nobledns_update", Path(__file__).parents[1] / "update.py")
mod = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)
class ConfigTests(unittest.TestCase):
    def test_filter_header_declares_subscription_title(self):
        self.assertTrue(mod.FILTER_HEADER.startswith("! Title: NobleDNS Filter\n"))
        self.assertIn("! Homepage: https://github.com/LucentDNS/NobleDNS\n", mod.FILTER_HEADER)
        self.assertIn("! Content: Listed domains are included as blocking targets only.\n", mod.FILTER_HEADER)

    def test_subscription_banner_includes_last_modified_and_block_count(self):
        rendered = mod.render_subscription(
            {"||example.com^", "||ads.example.net^"},
            {"@@||safe.example.org^"},
            "2026-11-12",
        )
        self.assertIn("! Last modified: 2026-11-12 (UTC)\n", rendered)
        self.assertIn("! Blocked domains: 2\n", rendered)
        self.assertIn("@@||safe.example.org^\n", rendered)

    def test_subscription_last_modified_is_stable_when_rules_are_unchanged(self):
        import json
        import tempfile
        from datetime import datetime, timezone
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "manifest.json").write_text(
                json.dumps({"built_at_utc": "2026-11-10T12:00:00+00:00"}),
                encoding="utf-8",
            )
            (root / "dns-filter.txt").write_text(
                "! Last modified: 2026-11-09 (UTC)\n"
                "||example.com^\n",
                encoding="utf-8",
            )
            result = mod.resolve_subscription_last_modified(
                {"||example.com^"},
                root / "manifest.json",
                datetime(2026, 11, 12, tzinfo=timezone.utc),
            )
            self.assertEqual(result, "2026-11-09")

    def test_subscription_last_modified_advances_when_rules_change(self):
        import tempfile
        from datetime import datetime, timezone
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "manifest.json").write_text("{}", encoding="utf-8")
            (root / "dns-filter.txt").write_text(
                "! Last modified: 2026-11-09 (UTC)\n"
                "||old.example^\n",
                encoding="utf-8",
            )
            result = mod.resolve_subscription_last_modified(
                {"||new.example^"},
                root / "manifest.json",
                datetime(2026, 11, 12, 8, tzinfo=timezone.utc),
            )
            self.assertEqual(result, "2026-11-12")

    def test_project_version_is_stable_semver(self):
        import re
        self.assertRegex(mod.VERSION_BASE, r"^\d+\.\d+\.\d+$")
        self.assertIn(f"! Version: {mod.VERSION_BASE}", mod.FILTER_HEADER)

    def test_proxy_url_validation(self):
        self.assertEqual(mod.validate_proxy_url("http://127.0.0.1:7897"), "http://127.0.0.1:7897")
        self.assertEqual(mod.validate_proxy_url("https://proxy.example:8443"), "https://proxy.example:8443")
        self.assertIsNone(mod.validate_proxy_url(None))
        for value in ("socks5://127.0.0.1:1080", "127.0.0.1:7897", "http://user:pass@127.0.0.1:7897", "http://proxy.example:70000", "http://proxy.example/path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mod.validate_proxy_url(value)


    def test_fetch_disables_ambient_proxy_when_no_proxy_is_supplied(self):
        from unittest.mock import patch

        data = b"||example.com^\n" * 10000

        class Response:
            status = 200
            headers = {"Content-Length": str(len(data))}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "https://source.example/filter.txt"
            def read(self, limit): return data

        with patch("urllib.request.build_opener") as build_opener:
            build_opener.return_value.open.return_value = Response()
            result = mod.fetch("https://source.example/filter.txt", None)
        self.assertEqual(result, data)
        handler = build_opener.call_args.args[0]
        self.assertEqual(handler.proxies, {})

    def test_fetch_rejects_https_to_http_redirect(self):
        from unittest.mock import patch

        class Response:
            status = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "http://source.example/filter.txt"

        with patch("urllib.request.build_opener") as build_opener, patch.object(mod.time, "sleep"):
            build_opener.return_value.open.return_value = Response()
            with self.assertRaisesRegex(RuntimeError, "Download failed after 5 attempts"):
                mod.fetch("https://source.example/filter.txt", None)

    def test_exactly_four_approved_sources(self):
        cfg = mod.load_config()
        self.assertEqual([x["key"] for x in cfg["sources"]], ["hagezi_pro_mini", "hagezi_tif_mini", "adguard_dns", "awavenue_ads"])
        self.assertEqual(cfg["sources"][0]["url"], "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.mini.txt")
        self.assertEqual(cfg["sources"][0]["min_bytes"], 1000000)
        self.assertEqual(cfg["sources"][0]["min_rules"], 50000)
        self.assertEqual(cfg["sources"][1]["url"], "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt")
        self.assertEqual(cfg["sources"][1]["min_bytes"], 1000000)
        self.assertEqual(cfg["sources"][1]["min_rules"], 100000)
        self.assertEqual(cfg["sources"][3]["min_bytes"], 10000)
        self.assertEqual(cfg["sources"][3]["min_rules"], 300)
        self.assertEqual(mod.UPSTREAM_LICENSES["hagezi_pro_mini"]["spdx"], "GPL-3.0")
        self.assertEqual(mod.UPSTREAM_LICENSES["hagezi_tif_mini"]["spdx"], "GPL-3.0")
        self.assertEqual(cfg["max_rules"], 500000)
    def test_drift_gate_blocks_large_source_change(self):
        import tempfile, json
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "manifest.json"
            p.write_text(json.dumps({"sources":{"adguard_dns":{"simple_block_rules":100}}}))
            with self.assertRaises(RuntimeError):
                mod.check_drift({"adguard_dns":{"supported_block_rules":130}}, set(), p, 15.0)

    def test_drift_gate_blocks_large_rule_set_delta(self):
        import tempfile, json
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "manifest.json"
            p.write_text(json.dumps({"sources":{}}))
            (Path(td) / "dns-filter.txt").write_text("! old\n" + "\n".join(f"||d{i}.example.com^" for i in range(100)))
            current = {f"||d{i}.example.com^" for i in range(90)} | {f"||new{i}.example.net^" for i in range(30)}
            with self.assertRaises(RuntimeError):
                mod.check_drift({}, current, p, 15.0)

    def test_drift_gate_blocks_absolute_rule_delta_even_below_percentage_limit(self):
        import tempfile, json
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "manifest.json"
            p.write_text(json.dumps({"sources":{}}))
            old_rules = {f"||d{i}.example.com^" for i in range(100_000)}
            (Path(td) / "dns-filter.txt").write_text("! old\n" + "\n".join(sorted(old_rules)))
            current = (
                old_rules
                - {f"||d{i}.example.com^" for i in range(3_001)}
                | {f"||new{i}.example.net^" for i in range(3_001)}
            )
            with self.assertRaisesRegex(RuntimeError, "absolute limit 3,000"):
                mod.check_drift({}, current, p, 15.0)
if __name__ == "__main__": unittest.main()
