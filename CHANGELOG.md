# Changelog

All notable changes to NobleDNS are documented here.

## Unreleased

### Added
- Add generated-subscription regression gates for 72 essential-service hostnames and 20 known advertising-infrastructure hostnames.
- Enforce an additional absolute drift ceiling of 3,000 rule additions and 3,000 removals per build, alongside the existing percentage-based source drift gate.
- Add subscription metadata for the last rule-set modification date and blocking-rule count; keep the date stable when rule content is unchanged.
- Publish verified build statistics and clarify that compiled domains are included as DNS blocking targets only.
- Preserve 193 documented upstream end-anchored exceptions (domain/subdomain and exact-hostname scope) and bound the active exception set at 250 to reject abnormal surges.
- Preserve documented end-anchored block patterns (`||domain^|` and `|domain^`) without widening them into domain/subdomain rules.
- Document the exact workflow for adding regression fixtures and updating their pinned counts.
- Add code and upstream rule-data license metadata to the generated subscription banner.
- Split the maintainer guide into separate English and Simplified Chinese documents while keeping their operational instructions aligned.

### Fixed
- Align the quality policy with the new regression corpus while explicitly limiting what the small sample can claim.
- Preserve the previous subscription modification date on identical rule content to avoid timestamp-only daily subscription churn.

- Preserve documented leading-dot DNS rules (`.domain^` and `.domain`) with subdomain-only semantics; reject malformed hostnames rather than broadening their scope.
- Model bare `||domain` rules without `^` as hostname-start patterns without an end separator in the critical-service regression gate.
- Apply exact supported `$badfilter` directives across the merged approved sources, record their targets and outcomes, and prevent disabled upstream rules from re-entering the subscription.
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
