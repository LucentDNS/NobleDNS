from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
FULL_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class WorkflowSecurityTests(unittest.TestCase):
    def test_all_external_actions_are_pinned_to_full_commit_shas(self):
        workflow_files = sorted(
            path for path in WORKFLOWS.rglob("*")
            if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
        )
        self.assertTrue(workflow_files, "No workflow files found")

        references = []
        for path in workflow_files:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                stripped = line.strip()
                if not stripped.startswith("uses:"):
                    continue
                reference = stripped[len("uses:"):].split("#", 1)[0].strip()
                if reference.startswith(("./", "docker://")):
                    continue
                references.append((path.relative_to(ROOT), number, reference))

        self.assertTrue(references, "No external action references found")
        for path, number, reference in references:
            with self.subTest(path=str(path), line=number, reference=reference):
                self.assertIn("@", reference, "External action must include a ref")
                _action, ref = reference.rsplit("@", 1)
                self.assertRegex(
                    ref,
                    FULL_COMMIT_SHA,
                    "External actions must be pinned to a full 40-character commit SHA",
                )

    def test_release_workflow_keeps_permissions_and_publish_guards_scoped(self):
        path = WORKFLOWS / "daily-build-release.yml"
        workflow = path.read_text(encoding="utf-8")

        self.assertIn("\npermissions:\n  contents: read\n", workflow)
        permission_blocks = re.findall(
            r"(?m)^    permissions:\n((?:      [^\n]+\n)+)",
            workflow,
        )
        self.assertEqual(
            permission_blocks,
            ["      contents: read\n", "      contents: write\n"],
            "Only build-test may read contents and publish may write contents",
        )
        self.assertIn("github.event_name != 'pull_request'", workflow)
        self.assertIn("needs.build-test.outputs.publish_update == 'true'", workflow)


if __name__ == "__main__":
    unittest.main()
