#!/usr/bin/env python3
"""Extract one dated SemVer section from CHANGELOG.md for a GitHub Release."""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def extract_release_notes(changelog: str, version: str) -> str:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError(f"Invalid stable SemVer version: {version}")

    heading_re = re.compile(
        rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}\s*$",
        re.MULTILINE,
    )
    matches = list(heading_re.finditer(changelog))
    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one dated changelog section for {version}; found {len(matches)}"
        )

    heading = matches[0]
    remainder = changelog[heading.end():]
    next_section = re.search(r"^## ", remainder, re.MULTILINE)
    body = remainder[:next_section.start()] if next_section else remainder
    body = body.strip()
    if not body:
        raise ValueError(f"Changelog section for {version} is empty")

    return f"# NobleDNS {version}\n\n{heading.group(0)}\n\n{body}\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    content = args.changelog.read_text(encoding="utf-8")
    notes = extract_release_notes(content, args.version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(notes, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
