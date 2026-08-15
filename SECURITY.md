# Security policy

## Supported versions

Until the first stable release, only the latest commit on `main` is supported.

## Reporting a vulnerability

Do not open a public issue containing credentials, tokens, telemetry values,
account identifiers, local paths, or proof-of-concept data from a real ZCode
installation.

After the repository is published, use GitHub's private vulnerability
reporting feature from the repository's **Security** tab. Include the affected
version, operating system, minimal reproduction steps, and sanitized evidence.
If private vulnerability reporting is unavailable, contact the repository
owner through GitHub before sharing sensitive details.

The maintainer will acknowledge a complete report when practical, investigate
it privately, and coordinate remediation and disclosure according to impact.

## Scope

Security-sensitive areas include profile encryption, native key storage,
filesystem ownership and permissions, process detection, transaction recovery,
backup integrity, and accidental secret disclosure.
