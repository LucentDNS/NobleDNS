# Changelog

All notable changes to NobleDNS are documented here.

## Unreleased

### Fixed
- Enforce the selected AdGuard DNS syntax contract and exclude unsupported leading-dot source rules with audit records.
- Restore the root-level `NobleDNS.txt` compatibility subscription as a byte-identical generated artifact.
- Add an evidence-gated project allowlist that generates active exceptions; keep upstream exceptions review-only.
- Add version and expiry metadata, strengthen proxy validation, and verify legacy/allowlist artifacts during publication.

## [1.1.0] - 2026-11-12

### Added
- Active project-maintained allowlist input with strict domain validation and regression coverage.
- Root-level `NobleDNS.txt` compatibility subscription generated alongside the canonical `dist/dns-filter.txt`.

### Changed
- Subscription metadata now declares the build version and a one-day refresh interval.
- The compiler publishes only `||domain^` and `||domain` forms; unsupported leading-dot source records are excluded and audited.
- Explicit proxy configuration is validated and ambient proxy discovery is disabled unless `--proxy` is supplied.


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
