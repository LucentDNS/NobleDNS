# Release and operations

## Daily schedule

The scheduled GitHub Actions run starts at 18:23 UTC (02:23 China Standard Time). GitHub scheduled workflows can be delayed during high load. Use Actions > NobleDNS daily build and release > Run workflow for an immediate manual run.

## Failure behavior

Any failed regression test, download, UTF-8 check, minimum source check, source drift gate, parser/output validation or rule cap stops the workflow before the commit/release steps. The previously committed `dist/` remains the public subscription. Inspect the Actions log and source changes before any manual override.

## Source drift override

Do not routinely use `--allow-large-change`. First compare the new upstream snapshot, inspect added/removed rules and syntax distribution, update regression tests if needed, then rebuild and publish through a reviewed workflow run.

## Rollback

Use GitHub Releases to identify the previous known-good subscription and revert the `dist/` update commit if the latest release causes confirmed regressions. Do not delete prior tags/releases until the issue is resolved.

## Repository setup

This repository is already configured for the public build and release workflow. Keep the workflow's permissions limited to repository contents, and do not add unrelated automation or credentials.

The first run has no published baseline, so the 15% drift check is not applied. Review the first public release carefully. Subsequent runs compare per-source counts and the actual rule-set additions/removals against the last published manifest. The workflow also retains a 30-day build-audit artifact containing exact source snapshots and compiler reports. For an unusually large upstream change, inspect it first, then manually dispatch the workflow with `allow_large_change` enabled.

If the default branch has branch protection that blocks direct pushes from GitHub Actions, configure an allowed release-bot path or adjust the workflow to open a pull request. The workflow must not be granted broader permissions than required.
