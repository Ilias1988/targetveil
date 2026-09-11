# Security policy

## Supported versions

TargetVeil is currently an alpha project. Security fixes are applied to the latest `main` branch and most recent tagged release.

## Reporting a vulnerability

Please do not include real client, target, credential or personal data in a report, issue, screenshot or test fixture.

For non-sensitive bugs, open a GitHub issue at:

https://github.com/Ilias1988/targetveil/issues

For a vulnerability that would expose user-entered data, bypass redaction, introduce remote communication or compromise the hosted application, use GitHub's private vulnerability reporting feature when it is available for the repository. If private reporting is unavailable, contact the maintainer through the links at https://ilias1988.me/ without sending exploit details publicly.

Include:

- the affected version or commit;
- a minimal synthetic reproduction;
- expected and actual behavior;
- the security impact;
- a suggested mitigation, if known.

Do not test with real engagement data. Do not intentionally access another person's data or disrupt the GitHub Pages site.

## Security-sensitive changes

Changes touching detectors, replacements, scope parsing, clipboard behavior, storage, CSP, service workers or deployment workflows should include regression tests and an update to the threat model when the security boundary changes.

