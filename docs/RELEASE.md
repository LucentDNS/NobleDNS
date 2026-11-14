# Release and operations

## Public update channel

The stable subscription URL is:

`https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt`

Validated scheduled builds update the subscription on the default branch. GitHub Releases are reserved for immutable, human-readable SemVer product versions (`vMAJOR.MINOR.PATCH`). Scheduled builds do not create hash-named Releases. Existing SemVer releases are not rewritten.

To publish a new product version, update `VERSION_BASE` in `update.py` and add the matching dated entry to `CHANGELOG.md` in the same reviewed change.

## 8-hour schedule

The scheduled GitHub Actions workflow runs three times daily: 18:23, 02:23 and 10:23 UTC (02:23, 10:23 and 18:23 China Standard Time, UTC+8). This matches the 8-hour expiry declared by HaGeZi TIF Mini. GitHub may delay scheduled workflows during periods of high load. For an immediate run, use Actions → NobleDNS scheduled build and release → Run workflow.

## Failure behavior

A failed regression test, download, UTF-8 check, minimum-source check, source-drift gate, parser/output validation or rule cap must stop publication. The last successfully committed subscription remains at the public URL. Inspect the Actions log and upstream changes before considering any override.

## Source drift

Do not routinely use `--allow-large-change`. First compare the new upstream snapshot, inspect added and removed rules and syntax distribution, update regression tests if necessary, then publish through the reviewed workflow.

## Rollback

If a newly published daily build causes a confirmed regression, identify the last known-good commit from the repository history and revert the affected `dist/` update through the repository's protected change process. SemVer releases remain immutable; do not treat a daily build as a new product version.

## Repository and permissions

Keep workflow permissions limited to the operations required for building and publishing repository contents. Do not add unrelated automation, credentials or broader permissions.

The workflow retains a 30-day build-audit artifact containing source snapshots and compiler reports. For unusually large upstream changes, inspect the evidence before manually dispatching the workflow with `allow_large_change` enabled.

Pull requests run build and regression checks. Publication is performed only by a successful run on the default branch.
