from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "daily-build-release.yml"


class PublicArtifactContractTests(unittest.TestCase):
    def test_badfilter_audit_is_copied_verified_and_released(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "cp build-output/latest/badfilter-audit.csv dist/badfilter-audit.csv",
            workflow,
        )
        self.assertIn("test -s dist/badfilter-audit.csv", workflow)
        self.assertIn("dist/badfilter-audit.csv", workflow)
        self.assertIn('"badfilter-audit.csv"', workflow)


if __name__ == "__main__":
    unittest.main()
