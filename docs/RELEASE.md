# Release and operations

## Public update channel

The stable subscription URL is:

`https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt`

Validated scheduled builds update the rolling subscription on the default branch. GitHub Releases are reserved for human-readable SemVer product-version snapshots (`vMAJOR.MINOR.PATCH`). Release assets are point-in-time snapshots and do not follow later scheduled data refreshes; users who want the current list should subscribe to the main-branch URL above. The publisher workflow treats each published version as immutable by policy: if the tag/release already exists, it refuses to retarget it or replace its assets. The current `v1.0.7` release reports `immutable: false` in GitHub's metadata, so this policy is not yet enforced by GitHub's platform-level release lock. To protect future releases, the repository owner must enable **Settings → Releases → Enable release immutability**. GitHub applies this setting only to future releases; existing v1.0.0–v1.0.7 releases are not retroactively protected.

To publish a new product version, update `VERSION_BASE` in `update.py` and add exactly one matching dated section to `CHANGELOG.md` in the same reviewed change. The workflow extracts only that version's section for the GitHub Release description.

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

The workflow retains each build-audit artifact for 5 days. A recent compressed artifact was about 16.9 MB; with three scheduled runs per day, five days of routine snapshots use roughly 254 MB before pull-request runs. This shorter retention keeps storage bounded on GitHub Free accounts (500 MB included artifact storage) while preserving a short investigation window. Source hashes, manifests and published subscription artifacts remain in the repository; do not rely on the temporary Actions artifact as permanent archival storage. For unusually large upstream changes, inspect the evidence before manually dispatching the workflow with `allow_large_change` enabled.

Pull requests run build and regression checks. Publication is performed only by a successful run on the default branch.
