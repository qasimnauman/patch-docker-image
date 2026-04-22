# Security Guidelines

## Credentials

- Use environment variables for registry credentials.
- Recommended names:
  - `DOCKERHUB_USERNAME`
  - `DOCKERHUB_PASSWORD`
- Do not pass passwords on the command line.
- In CI, store credentials in your secret manager (for GitHub Actions, use `secrets.*`).

## Private Data Handling

- The tool avoids logging credential values.
- Scout reports can include rich vulnerability metadata. Treat report artifacts as sensitive.
- Avoid committing raw reports to public repositories unless reviewed and sanitized.

## Responsible Usage

- Always run post-patch verification before promoting an image.
- Keep base images and runtime dependencies updated.
- Use least-privilege tokens for container registry operations.
