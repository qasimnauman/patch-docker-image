# docker-vuln-patcher

Production-oriented Docker image vulnerability patcher for Node.js and Python images.

## What It Does

1. Uses Docker Scout to scan an image.
2. Creates a patch plan for fixable CVEs.
3. Generates a patch Dockerfile artifact.
4. Builds the patched image.
5. Re-scans the patched image.
6. Fails unless selected fixable CVEs are no longer present.
7. Optionally pushes the verified image.

## Current Support

- Runtime scope: Node.js and Python images
- Package scopes:
  - OS package managers (`apt`, `apk`, `yum`, `dnf`) when present
  - `npm`
  - `pip`
- Unsupported runtime families are rejected safely.

## Project Layout

```text
.github/
  actions/
    patch-docker-image/
      action.yml
      README.md
  workflows/
    e2e-live-smoke.yml
    release-action-tags.yml
action.yml
src/
  docker_vuln_patcher/
    __init__.py
    __main__.py
    cli.py
templates/
  github-actions/
    consume-composite-action.yml
    patch-image.yml
scripts/
  build_linux_binary.sh
tests/
  test_cli.py
patch_image.py
pyproject.toml
README.md
SECURITY.md
```

## Installation

### From source

```bash
python -m pip install --upgrade pip
pip install .
```

After install, the command is:

```bash
docker-vuln-patcher --help
```

## Usage

### A) Patch existing image from registry

```bash
docker-vuln-patcher \
  --image myrepo/myapp:latest \
  --non-interactive \
  --report-dir ./vuln_reports
```

### B) Build from Dockerfile, then patch

```bash
docker-vuln-patcher \
  --image myrepo/myapp:latest \
  --dockerfile-path ./Dockerfile \
  --context-path . \
  --build-arg APP_ENV=prod \
  --non-interactive \
  --report-dir ./vuln_reports
```

### C) Patch, verify, and push

```bash
docker-vuln-patcher \
  --image myrepo/myapp:latest \
  --non-interactive \
  --push
```

## Credential Handling (Secure by Default)

- Credentials are read from environment variables.
- Password is sent using `docker login --password-stdin`.
- Password value is never logged.

Required env vars for non-interactive CI:

```bash
export DOCKERHUB_USERNAME="your-user"
export DOCKERHUB_PASSWORD="your-password-or-token"
```

## GitHub Actions Flow

Use one of these:

- `templates/github-actions/patch-image.yml` (local action in same repo)
- `templates/github-actions/consume-composite-action.yml` (other repos)

Public action entrypoint:

- `action.yml` (repository root)

Backward-compatible internal action path:

- `.github/actions/patch-docker-image/action.yml`

Live smoke workflow in this repo:

- `.github/workflows/e2e-live-smoke.yml`

Set repository secrets:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_PASSWORD`

Then run via `workflow_dispatch` and pass the target image.

## Reusable GitHub Composite Action

### Use in same repository

```yaml
jobs:
  patch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: patch
        uses: ./
        with:
          image: myrepo/myapp:latest
          push: "true"
          dh-user: ${{ secrets.DOCKERHUB_USERNAME }}
          dh-password: ${{ secrets.DOCKERHUB_PASSWORD }}
```

### Use from another repository

```yaml
jobs:
  patch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: patch
        uses: qasimnauman/patch-docker-image@v1
        with:
          image: myrepo/myapp:latest
          push: "true"
          dh-user: ${{ secrets.DOCKERHUB_USERNAME }}
          dh-password: ${{ secrets.DOCKERHUB_PASSWORD }}
```

Pin the action to a release tag or commit SHA in production.

## Publish Stable Action Tags

To let internet users consume your action with `@v1`, publish tags from:

- `.github/workflows/release-action-tags.yml`

Run it with inputs like:

- `version`: `v1.0.0`
- `major`: `v1`

Then users can reference:

```yaml
uses: qasimnauman/patch-docker-image@v1
```

## Linux Executable Binary (Current Focus)

Use the helper script:

```bash
./scripts/build_linux_binary.sh
```

This creates a standalone binary under `dist/` via PyInstaller.

## Notes

- Post-patch verification is mandatory in non-dry-run mode.
- If fixable CVEs remain after patch build, the command exits with failure.
- The generated patch Dockerfile is always saved under `vuln_reports/patches/`.
- Some base images may still report fixable CVEs after package updates. The verification gate prevents false success and fails the run.
