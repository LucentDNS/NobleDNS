# Changelog

All notable changes to NobleDNS are documented here.

## Unreleased

### Changed
- Rework the project homepages to lead with user value, the single balanced edition, mainland-use priorities and practical subscription guidance.
- Keep detailed verification scope and evidence limitations in the quality documentation rather than foregrounding them as a warning block on the homepage.

### Changed
- Clarify NobleDNS as a single balanced edition designed with mainland China everyday network compatibility as a primary consideration.
- Document conservative rule acceptance, domestic-service review priorities and evidence requirements for future low-false-positive claims.
- Add a Chinese-language project overview and a formal single-edition policy.

## [1.0.0] - 2026-11-12

### Added
- Public release workflow that publishes validated subscription and audit artifacts.
- Public feedback guidance for blocking and compatibility reports.

### Changed
- NobleDNS is maintained and published as a public DNS filtering rule set.
- Main-branch pushes run the complete build, validation and publication process.
- Documented the difference between parser/build validation and real-world filtering efficacy.
- Added an immutable SemVer release alongside content-addressed audit Releases.

### Fixed
- Corrected GitHub Actions output handling so the release identity hash is passed to the publication job.

## Historical notes

Earlier development milestones and the RC2.2 reproducibility baseline are retained as historical engineering records in [docs/RC2.2-BASELINE.md](docs/RC2.2-BASELINE.md).

## Changelog maintenance

- Keep changes that are not yet released under the Unreleased section.
- Move changes into a versioned section only when that version is actually released.
- Use the actual release version and release date; do not fabricate historical release entries.
- Record meaningful project changes rather than routine build noise.
