# Security Policy

## Supported versions

Security fixes are provided for the latest published Atlaso release and the current `main` branch while a fix is being
prepared.

## Atlaso data classification

Atlaso treats IP addresses, MAC addresses, hostnames, and account names as non-sensitive operational identifiers when
they appear by themselves.

Passwords, tokens, authenticated URLs, session material, private keys, password-, credential-, or secret-derived
hashes, and other secret-bearing data are sensitive. Content-integrity hashes of non-secret material are not sensitive
by themselves. An operational identifier becomes sensitive when it is embedded in or paired with authentication or
cryptographic material.

This classification does not make authenticated or access-restricted data public, bypass authorization, or override an
operator's site or organization handling requirements. Review the complete context before sharing logs, audits,
screenshots, or diagnostics. When the context is uncertain, keep the material private and use the vulnerability
reporting process below.

## Reporting a vulnerability

Please do not report security vulnerabilities in public GitHub issues, discussions, pull requests, or chat channels.

Use the repository's **Security** tab and select **Report a vulnerability**, or open a
[private vulnerability report](https://github.com/mdaneri/Atlaso/security/advisories/new), to submit a private GitHub
Security Advisory. Include the affected version, reproduction steps, impact, and any proof of concept. We will
acknowledge a valid report within seven days and coordinate disclosure after a fix or mitigation is available.

Use ordinary bug reports only for non-sensitive defects.
