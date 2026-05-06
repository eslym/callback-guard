# Security Policy

## Supported Versions

This project is currently maintained on the `main` branch.

## Reporting a Vulnerability

Please do not open public issues for suspected vulnerabilities.

Report security issues privately by emailing the maintainer listed in the repository profile and include:

- A clear description of the issue and impact.
- Reproduction steps or a proof-of-concept.
- Any relevant logs or configuration snippets (redact secrets).

We will acknowledge reports as quickly as possible and coordinate remediation and disclosure timelines.

## Hardening Guidance

For high-security deployments, enable the `security` opt-ins in `README.md` (strict request validation,
metadata endpoint blocking, destination port allowlist, and auth rate limiting), and combine with network-level
controls (firewall rules and egress restrictions).
