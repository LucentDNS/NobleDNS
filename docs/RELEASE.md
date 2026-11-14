# Release and operations

## Public update channel

The stable subscription URL is:

`https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt`

Validated scheduled builds update the rolling subscription on the default branch. GitHub Releases are reserved for human-readable SemVer product-version snapshots (`vMAJOR.MINOR.PATCH`). Release assets are point-in-time snapshots and do not follow later scheduled data refreshes; users who want the current list should subscribe to the main-branch URL above. Scheduled builds do not create hash-named Releases. The publisher workflow does not rewrite existing stable release assets or retarget their tags.

## GitHub-enforced release immutability

The current `v1.0.7` release reports `immutable: false` in GitHub's release metadata. Therefore, the no-rewrite behavior is currently enforced by NobleDNS's publisher-workflow policy, not by GitHub's platform-level immutable-release lock.

To protect future releases at the GitHub platform level, enable **Settings → Releases → Enable release immutability**. GitHub applies this setting only to releases published after it is enabled; it will not retroactively lock the existing `v1.0.7` release. Verify a future release by checking for the **Immutable** label or running `gh release verify <tag>`. See [GitHub's immutable-release documentation](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) and [enablement instructions](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes).

To publish a new product version, update `VERSION_BASE` in `update.py` and add the matching dated entry to `CHANGELOG.md` in the same reviewed change.

## 8-hour schedule

The scheduled GitHub Actions workflow runs three times daily: 18:23, 02:23 and 10:23 UTC (02:23, 10:23 and 18:23 China Standard Time, UTC+8). This matches the 8-hour expiry declared by HaGeZi TIF Mini. GitHub may delay scheduled workflows during periods of high load. For an immediate run, use Actions → NobleDNS scheduled build and release → Run workflow.

## Failure behavior

A failed regression test, download, UTF-8 check, minimum-source check, source-drift gate, parser/output validation or rule cap must stop publication. The last successfully committed subscription remains at the public URL. Inspect the Actions log and upstream changes before considering any override.

## Source drift

Do not routinely use `--allow-large-change`. First compare the new upstream snapshot, inspect added and removed rules and syntax distribution, update regression tests if necessary, then publish through the reviewed workflow.

## Rollback

If a newly published daily build causes a confirmed regression, identify the last known-good commit from the repository history and revert the affected `dist/` update through the repository's protected change process. Existing SemVer release assets and tags are not rewritten by the publisher workflow; do not treat a daily build as a new product version.

## Repository and permissions

Keep workflow permissions limited to the operations required for building and publishing repository contents. Do not add unrelated automation, credentials or broader permissions.

The workflow retains a 30-day build-audit artifact containing source snapshots and compiler reports. For unusually large upstream changes, inspect the evidence before manually dispatching the workflow with `allow_large_change` enabled.

Pull requests run build and regression checks. Publication is performed only by a successful run on the default branch.
