# Dedicated Release Publisher

## Purpose

NobleDNS publishes validated subscription artifacts to the default branch. The publisher must be able to update release files, but ordinary build and pull-request jobs must not receive write credentials.

The release workflow therefore uses a dedicated GitHub App installation token instead of granting `contents: write` to the workflow's default `GITHUB_TOKEN`.

This is a repository-specific publishing identity, not a general-purpose automation account.

## GitHub App configuration

Create a GitHub App owned by the `LucentDNS` account.

Recommended settings:

- App name: `NobleDNS Publisher` (or another unique name available to the account).
- Homepage URL: `https://github.com/LucentDNS/NobleDNS`.
- Webhook: inactive; no webhook URL or webhook secret is required.
- Repository permissions:
  - Contents: Read and write.
  - All other repository permissions: No access.
  - No organization permissions.
  - No user permissions.
- Install the App on **Only select repositories**, selecting only `NobleDNS`.

Do not grant this App access to other repositories. Do not grant administration, workflows, actions, pull requests, or secrets permissions.

Generate a private key for the App and store it securely. Never commit the private key or paste it into an issue, pull request, chat, or workflow log.

## Repository configuration

### 1. Repository variable

In **Settings → Secrets and variables → Actions → Variables**, create:

| Name | Value |
|---|---|
| `NOBLEDNS_PUBLISHER_CLIENT_ID` | The GitHub App Client ID |

The Client ID is an identifier, not a private key.

### 2. Protected environment

In **Settings → Environments**, create an environment named:

`release`

Configure deployment branches to allow **Selected branches and tags** and select only:

`main`

Under this environment's secrets, create:

| Name | Value |
|---|---|
| `NOBLEDNS_PUBLISHER_PRIVATE_KEY` | The complete PEM private key generated for the NobleDNS Publisher App |

Do not put the private key in a repository-wide Actions secret. The workflow references it only from the `release` environment. The environment's branch restriction prevents pull-request and non-main workflow runs from receiving it.

Do not configure required reviewers for this environment if unattended daily publication is required; a required reviewer would pause scheduled publication pending human approval.

## Ruleset configuration

Edit the active `Protect main` ruleset. Preserve the existing deletion and force-push protections, then configure:

1. **Require a pull request before merging**.
2. **Require status checks to pass** and select the exact check name `Build and validate`.
3. Require branches to be up to date before merging, if the option is available.
4. Add the **NobleDNS Publisher** GitHub App under **Bypass list → Apps**, with bypass mode **Always allow**.

The App bypass is necessary because the publisher updates generated artifacts directly on `main` after validation. Use the App identity, not the generic GitHub Actions actor, as the bypass actor. Do not add repository administrators, maintainers, or broad roles to the bypass list merely to make automation work.

The App's bypass permission is still powerful: any workflow that can obtain this App's installation token could use it. Keep the private key in the protected `release` environment, keep that environment restricted to `main`, and review every change to workflow files carefully.

A pull-request requirement does not itself require an approval. This project is maintained by a small maintainer set; do not enable a one-approval requirement unless an independent reviewer is actually available. The required validation check must remain mandatory.

## Workflow security properties

The release job:

- Runs only for non-PR events on the repository's default branch and only when the validated output has a substantive update.
- Runs after the `Build and validate` job succeeds.
- Uses a repository-scoped installation token with only `contents: write`.
- Keeps the workflow's default `GITHUB_TOKEN` permission at `contents: read`.
- Uses the App token for the authenticated checkout, Git push, and GitHub Release operations.
- Retains the branch SHA guard so a build cannot publish after the default branch has advanced.
- Does not publish from pull-request or non-default branches.

The installation token is short-lived and is created only for the publishing job. The action revokes it at job completion.

## Activation order

Do not enable the new branch rules before all of the following are complete:

1. Create and install the GitHub App with the permissions above.
2. Create the `release` environment, restrict it to `main`, and add the private-key secret.
3. Add the Client ID repository variable.
4. Confirm that the App is visible in the ruleset Apps bypass picker.
5. Merge the workflow change.
6. Add the App as the only publishing bypass actor.
7. Enable PR and required-status-check rules.
8. Run a manual workflow dispatch on `main` and confirm that a real artifact update can publish successfully. A no-change run is not sufficient to prove write access; inspect the publisher job's token creation and authentication steps, and perform a controlled release-path test before relying on unattended publication.

If the App or environment is not configured, the publishing job is expected to fail closed rather than silently fall back to a broad `GITHUB_TOKEN` write permission.

## Operational response

If the publisher token cannot be created, the App installation is missing, or the environment is unavailable:

- Do not restore broad `contents: write` permissions to the default workflow token as a quick fix.
- Inspect the App installation, repository selection, permission grant, Client ID variable, environment secret, and environment branch restriction.
- Keep the validated build artifact for investigation.
- Resume publication only after the scoped publisher identity is working.
