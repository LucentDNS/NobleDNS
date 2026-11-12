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

    def test_release_workflow_records_hosted_runner_provenance(self):
        path = WORKFLOWS / "daily-build-release.yml"
        workflow = path.read_text(encoding="utf-8")

        self.assertEqual(workflow.count("runs-on: ubuntu-24.04"), 2)
        self.assertNotIn("runs-on: ubuntu-latest", workflow)
        self.assertIn("Record build environment provenance", workflow)
        self.assertIn("image_version=", workflow)
        self.assertIn('test -s "$OUT/build-environment.txt"', workflow)

    def test_daily_updates_do_not_create_candidate_or_content_addressed_releases(self):
        path = WORKFLOWS / "daily-build-release.yml"
        workflow = path.read_text(encoding="utf-8")

        self.assertNotIn("content-addressed Release", workflow)
        self.assertNotIn('gh release create "$TAG"', workflow)
        self.assertIn('VERSION_TAG="v$VERSION"', workflow)
        self.assertIn('gh release create "$VERSION_TAG"', workflow)

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
            ["      contents: read\n", "      contents: read\n"],
            "Both jobs must keep the default GITHUB_TOKEN read-only",
        )
        self.assertIn("environment:\\n      name: release", workflow)
        self.assertIn(
            "uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510",
            workflow,
        )
        self.assertIn("permission-contents: write", workflow)
        self.assertIn("private-key: ${{ secrets.NOBLEDNS_PUBLISHER_PRIVATE_KEY }}", workflow)
        self.assertIn("token: ${{ steps.publisher-token.outputs.token }}", workflow)
        self.assertIn("GH_TOKEN: ${{ steps.publisher-token.outputs.token }}", workflow)
        self.assertNotIn("GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}", workflow)
        self.assertIn("github.event_name != 'pull_request'", workflow)
        self.assertIn("needs.build-test.outputs.publish_update == 'true'", workflow)
        self.assertEqual(workflow.count("persist-credentials: false"), 1)
        self.assertEqual(workflow.count("persist-credentials: true"), 1)


if __name__ == "__main__":
    unittest.main()
