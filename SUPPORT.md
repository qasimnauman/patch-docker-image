# Support Policy

Last updated: 2026-04-22

This document defines support expectations for patch-docker-image.

## 1. Supported Components

Support is provided for:

- public GitHub Action usage via `qasimnauman/patch-docker-image@v1`;
- CLI usage via `docker-vuln-patcher`;
- documented runtime scope (Node.js and Python images).

## 2. Support Channels

- General support and bug reports:
  [GitHub Issues](https://github.com/qasimnauman/patch-docker-image/issues)
- Security issues:
  follow SECURITY.md and avoid posting sensitive details in public issues.

## 3. What to Include in a Support Request

To help triage quickly, include:

- Product mode (Action or CLI);
- command/workflow used;
- target image reference;
- non-sensitive logs and error output;
- generated report excerpts (sanitized);
- environment details (runner OS, Docker version, Docker Scout version).

Do not include plaintext credentials or tokens.

## 4. Response and Resolution

Support is provided on a best-effort basis.

- No guaranteed response time or SLA is offered.
- Priority is typically given to reproducible bugs, security concerns, and regressions.

## 5. Out of Scope

The following are generally out of scope:

- support for unsupported runtime families;
- issues caused by third-party service outages;
- custom environment hardening outside Product behavior;
- legal/compliance advice specific to your organization.

## 6. Versioning and Compatibility

- Consumers should pin to a stable major tag (`@v1`) or commit SHA.
- Breaking changes may be introduced in future major versions.
- Older versions may receive limited or no maintenance.

## 7. Change Management

Support policy may be updated from time to time. The current version in the default branch is authoritative.
