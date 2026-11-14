import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DocumentationConsistencyTests(unittest.TestCase):
    def test_chinese_maintainer_guide_matches_configured_sources(self):
        config = json.loads((ROOT / "config" / "sources.json").read_text(encoding="utf-8"))
        guide = (ROOT / "docs" / "MAINTAINER-GUIDE.zh-CN.md").read_text(encoding="utf-8")

        self.assertIn("当前固定使用四个互补上游", guide)
        for source in config["sources"]:
            self.assertIn(source["name"], guide)
        self.assertNotIn("| HaGeZi Multi Normal |", guide)
        self.assertIn("不并行集成 Multi Normal", guide)

    def test_benchmark_plan_does_not_describe_multi_normal_as_production(self):
        plan = (ROOT / "docs" / "REAL-WORLD-BENCHMARK-PLAN.md").read_text(encoding="utf-8")
        lowered = plan.lower()

        self.assertIn("HaGeZi Multi Normal is **not** a production input", plan)
        self.assertNotIn("both are production inputs", lowered)
        self.assertNotIn("already configured production inputs", lowered)
        self.assertNotIn("added alongside Multi Normal", plan)

    def test_frozen_comparator_baseline_matches_frozen_chinese_audit(self):
        baseline = (ROOT / "docs" / "COMPARATOR-BASELINE-2026-11-14.md").read_text(encoding="utf-8")
        chinese_audit = (ROOT / "docs" / "ADGUARD-CHINESE-DNS-AUDIT.md").read_text(encoding="utf-8")
        baseline_match = re.search(
            r"^> NobleDNS: v[^;]+; subscription SHA-256: `([0-9a-f]{64})`.$",
            baseline,
            flags=re.MULTILINE,
        )
        audit_match = re.search(
            r"Matching NobleDNS build: v[^,]+, subscription SHA-256 `([0-9a-f]{64})`",
            chinese_audit,
        )

        self.assertIsNotNone(baseline_match, "Comparator baseline must declare its frozen subscription hash")
        self.assertIsNotNone(audit_match, "Chinese audit must declare the matching frozen subscription hash")
        self.assertEqual(baseline_match.group(1), audit_match.group(1))
        self.assertIn("actions/runs/43579323077", baseline)
        self.assertIn("actions/runs/43579323077", chinese_audit)


if __name__ == "__main__":
    unittest.main()
