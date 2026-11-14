# Changelog

All notable changes to NobleDNS are documented here. Versioned sections describe the matching published SemVer release; routine upstream refreshes do not create new product versions.

## Unreleased

### Added
- Add a reproducible, audit-only review of AdGuard's Chinese browser filter and its DNS-scope candidates; do not import browser-context rules into the production DNS subscription.
- Document AdGuard's dedicated Chinese DNS source sections, shared exclusions and the rationale for keeping the current production source set unchanged.
- Record an updated mature-list differential baseline and align hostname benchmark scoring with production validation by excluding IP literals from hostname counts.

### Changed
- Switch the HaGeZi Multi base source from the full PRO list to the size-optimized PRO Mini list; retain the same four-source composition pending post-switch differential validation.
- Clarify that exact-rule overlap and automated build success are not measurements of real-world efficacy, precision, recall or client compatibility.
- Retain large build-audit artifacts for 5 days rather than 30 to keep recurring Actions storage within a conservative budget.

## [1.0.7] - 2026-11-14

### Changed
- Run scheduled upstream refreshes three times daily at 8-hour intervals to align with HaGeZi TIF Mini's declared subscription expiry.
- Set the generated subscription expiry metadata to 8 hours.

## [1.0.6] - 2026-11-14

### Added
- Add HaGeZi TIF Mini as a threat-intelligence supplement alongside HaGeZi Multi PRO Mini.
- Add HaGeZi Multi PRO Mini as the sole HaGeZi Multi tier and remove Multi Normal from production inputs, following the upstream cumulative-tier model.
- Complete the four-source production composition with AdGuard DNS Filter and AWAvenue Ads-only.
- Record the exact comparison against the previous v1.0.5 subscription: 68,404 duplicate rules and 117,911 incremental rules; the resulting build contained 457,446 blocking rules and 11 inherited exceptions.

### Changed
- Keep the 500,000-rule ceiling as a hard limit, not a target; retain source drift and output validation gates.

## [1.0.5] - 2026-11-14

### Added
- Add the dedicated AWAvenue Ads-only AdGuard DNS variant as a focused advertising supplement.
- Add generated-subscription regression sentinels for 72 essential-service hostnames and 20 known advertising hostnames.
- Add an absolute drift ceiling of 3,000 additions and 3,000 removals per build, alongside the percentage-based source drift gate.
- Add subscription last-modified metadata, active-exception limits and upstream licensing metadata.

### Changed
- Preserve supported AdGuard DNS wildcard hostname patterns and the documented `$important` modifier without rewriting their semantics.
- Clarify the distinction between parser/build validation and real-world filtering effectiveness.

## [1.0.4] - 2026-11-14

### Fixed
- Preserve supported upstream wildcard hostname rules and `$important` priority semantics without rewriting their patterns; continue excluding dynamic-suffix and ambiguous patterns.

## [1.0.3] - 2026-11-12

### Fixed
- Exclude undocumented leading-dot hostname patterns from the public DNS subscription and retain all excluded source lines in the parser audit.
- Preserve documented `||domain` rules without an explicit `^`; do not apply a blanket trailing-caret rejection.
- Disable implicit environment-proxy discovery when no proxy is specified and reject HTTPS-to-HTTP source redirects.

## [1.0.2] - 2026-11-12

### Changed
- Activate the 11 supported simple upstream exception rules in the main subscription, preserving their source compatibility intent while excluding unsupported complex exception syntax.
- Publish `dist/allowlist-active.txt` and record active exception counts in the manifest and validation report.

### Fixed
- Keep the root-level `NobleDNS.txt` subscription byte-identical to `dist/dns-filter.txt`.
- Include version and expiry metadata in the filter header and verify it against the manifest.

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
- Publish the first public NobleDNS subscription and validated release artifacts.
- Add public feedback guidance for blocking and compatibility reports.

### Changed
- Run build, validation and publication through the main-branch workflow.
- Document the distinction between build integrity and real-world filtering efficacy.

### Fixed
- Correct GitHub Actions output handling so the release identity hash is passed to the publication job.

## Historical notes

Earlier development milestones and the RC2.2 reproducibility baseline are retained as historical engineering records in [docs/RC2.2-BASELINE.md](docs/RC2.2-BASELINE.md).

## Changelog maintenance

- Keep unreleased work under `[Unreleased]`.
- Add a dated version section only when preparing the matching SemVer release.
- Use the actual release version and release date; do not fabricate historical release entries.
- The release workflow extracts only the matching version section for GitHub Release notes; it never publishes the entire changelog as a release description.
- Record meaningful project changes rather than routine upstream refresh noise.
