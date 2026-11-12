# Changelog

All notable changes to NobleDNS are documented here.

## Unreleased

### Fixed
- Exclude undocumented leading-dot hostname patterns from the public DNS subscription and retain all excluded source lines in the parser audit.
- Preserve documented `||domain` rules without an explicit `^`; do not apply a blanket trailing-caret rejection.
- Disable implicit environment-proxy discovery when no proxy is specified and reject HTTPS-to-HTTP source redirects.
- Bump the next immutable release to 1.0.3; keep v1.0.2 unchanged.

## [1.0.2] - 2026-11-12

### Changed
- Activate the 11 supported simple upstream exception rules in the main subscription, preserving their source compatibility intent while excluding unsupported complex exception syntax.
- Publish `dist/allowlist-active.txt` and record active exception counts in the manifest and validation report.

### Fixed
- Keep the root-level `NobleDNS.txt` subscription byte-identical to `dist/dns-filter.txt`.
- Include `Version` and `Expires: 1 day` metadata in the filter header and verify it against the manifest.
- Keep the SemVer release immutable and versioned independently from content-addressed audit releases.

## [1.0.1] - 2026-11-12

### Fixed
- Restore the legacy root-level `NobleDNS.txt` compatibility subscription.
- Add filter version and one-day expiry metadata.
- Validate explicit HTTP(S) proxy URLs and reject embedded credentials.

### Changed
- Clarify upstream exception review and cross-source precedence requirements.
- Refine the project homepages to lead with user value, the single balanced edition and practical subscription guidance.
- Define the single balanced mainland-oriented edition and add the Chinese-language project overview and edition policy.

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
