import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "extract_release_notes",
    Path(__file__).parents[1] / "tools" / "extract_release_notes.py",
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class ReleaseNotesTests(unittest.TestCase):
    def test_extracts_only_requested_version_section(self):
        changelog = """# Changelog

## Unreleased

### Added
- Future work.

## [1.2.3] - 2026-11-14

### Fixed
- Version-specific fix.

## [1.2.2] - 2026-11-13

### Added
- Older feature.
"""
        notes = mod.extract_release_notes(changelog, "1.2.3")
        self.assertIn("# NobleDNS 1.2.3", notes)
        self.assertIn("- Version-specific fix.", notes)
        self.assertNotIn("Future work", notes)
        self.assertNotIn("Older feature", notes)

    def test_missing_version_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "found 0"):
            mod.extract_release_notes("# Changelog\n\n## [1.0.0] - 2026-11-12\n\nOK", "1.0.1")

    def test_duplicate_version_fails_closed(self):
        text = "## [1.0.0] - 2026-11-12\n\nA\n\n## [1.0.0] - 2026-11-13\n\nB"
        with self.assertRaisesRegex(ValueError, "found 2"):
            mod.extract_release_notes(text, "1.0.0")

    def test_empty_version_section_fails_closed(self):
        text = "## [1.0.0] - 2026-11-12\n\n## [0.9.0] - 2026-11-11\n\nOld"
        with self.assertRaisesRegex(ValueError, "empty"):
            mod.extract_release_notes(text, "1.0.0")

    def test_rejects_non_semver(self):
        with self.assertRaisesRegex(ValueError, "Invalid stable SemVer"):
            mod.extract_release_notes("## [latest] - 2026-11-14\n\nText", "latest")


if __name__ == "__main__":
    unittest.main()
