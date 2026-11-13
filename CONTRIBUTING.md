# Contributing to NobleDNS

Thank you for helping improve NobleDNS. The project prioritizes compatibility, evidence, narrow rule scope, reproducible builds, and clear provenance over maximum rule count.

## Before opening a pull request

- Search existing issues and pull requests for the same report.
- Explain the user-visible problem or maintenance benefit.
- Keep changes focused and avoid unrelated formatting or generated-file churn.
- Do not include personal information, credentials, tokens, or unredacted DNS logs.

## Rule and source changes

A domain name or its appearance in another blocklist is not sufficient evidence by itself.

For a proposed rule correction, include:

1. The exact hostname and affected site, app, or function.
2. The source list, exact source line, and source snapshot or commit.
3. The observed advertising, tracking, unwanted telemetry, threat, or compatibility behavior.
4. Reproduction steps and relevant sanitized DNS evidence.
5. The narrowest rule scope supported by the evidence.
6. Any affected parent domain, subdomains, shared hosting, CDN, login, payment, push, update, or other service dependency.
7. Regression coverage for a confirmed correction.

Do not add a new upstream source or broaden parser syntax without a separate review of its license, provenance, update behavior, grammar, client semantics, and compatibility impact.

## Exception rules

DNS exceptions can override matching blocking rules and therefore require particular care.

- Follow the exception review procedure in docs/EXCEPTION-REVIEW.md.
- Never mark an exception approved without a reviewer, UTC review date, rationale, evidence URL, and scope assessment.
- Do not set baseline_active=true for new entries. That flag is reserved for the exact inherited legacy baseline encoded in the builder.
- New unreviewed exceptions must fail the build; do not bypass the gate to make a build pass.
- Rejected, retired, or unresolved entries must retain their audit trail.

## Local validation

Use Python 3.12.

Install the pinned dependencies:

```sh
python -m pip install --requirement requirements.txt
```

Run the complete regression suite:

```sh
python -m unittest discover -s tests -v
```

Build against the configured upstream sources and the previous manifest:

```sh
python update.py --out build-output --previous-manifest dist/manifest.json
```

Run the generated-subscription quality gates:

**Linux/macOS**

```sh
NOBLEDNS_FILTER_PATH=build-output/latest/dns-filter.txt python -m unittest discover -s tests -p 'quality_gates.py' -v
```

**PowerShell**

```powershell
$env:NOBLEDNS_FILTER_PATH = "build-output/latest/dns-filter.txt"
python -m unittest discover -s tests -p "quality_gates.py" -v
```

Inspect the generated manifest, validation report, parser exclusions, syntax audit, active exception list, and rule diff before proposing publication. Do not use --allow-large-change unless the upstream change has been inspected and the reason is documented.

## Generated files and releases

Do not hand-edit generated subscription files or manifest counts. Change the source data, policy, or builder and let the validated workflow regenerate artifacts. Do not create or publish a release manually as part of an ordinary rule-change pull request.

## Pull request expectations

- Use a focused branch and pull request against main.
- Describe the change, evidence, risk, and tests performed.
- Keep CI passing; do not merge around failed checks.
- Update relevant documentation when behavior or policy changes.
- Preserve applicable copyright, attribution, and license notices.

The project may request additional evidence or decline changes that cannot be validated safely.
