# Changelog

All notable project changes are documented in this file.

The project is currently an RC3 automation candidate and has not yet
been qualified for production use.

## [Unreleased]

### Added

- Added automatic build and validation checks for pushes to the `main` branch.
- Added parser support for preserving `.domain^` and `.domain` leading-dot rules without rewriting their syntax.
- Added a real upstream regression fixture covering 28 records: 27 accepted rules and one trailing-dot rule that remains excluded.

### Changed

- Separated push-triggered build and validation from candidate release publishing; pushes do not execute the publish job.

### Fixed

- Enforced strict IDNA2008 validation for Punycode A-labels.
- Added decode-and-re-encode consistency checks to reject invalid Punycode labels.

### Documentation

- Added the personal maintainer guide.
- Clarified that leading-dot parser regression coverage does not establish broad DNS-client compatibility or production qualification.

## Changelog maintenance

- Keep unreleased changes under `[Unreleased]`.
- Move changes into a versioned section only when that version is actually released.
- Use the actual release version and release date; do not fabricate historical release entries.
- Organize entries under the following categories when applicable:
  - Added
  - Changed
  - Deprecated
  - Removed
  - Fixed
  - Security
  - Documentation
- Record meaningful project changes rather than routine build noise.
- Do not describe existing behavior as a new change unless it was actually introduced or modified in that release.
