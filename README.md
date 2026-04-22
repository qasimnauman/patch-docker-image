# patch-docker-image

Production-ready Docker image vulnerability patching for Node.js and Python container images.

This project provides:
- A CLI tool (`docker-vuln-patcher`) for local and CI/CD usage
- A public reusable GitHub Action (`qasimnauman/patch-docker-image@v1`)
- Verification gating that fails the run if targeted fixable CVEs still remain

## Why This Project

Most patch automation flows stop at "build succeeded". This project enforces a stronger rule:
- Scan
- Patch
- Re-scan
- Fail unless targeted fixable vulnerabilities are actually reduced to zero for selected severities

This prevents false-success pipelines and gives safer production outcomes.

## Scope

Supported runtime families:
- Node.js images
- Python images

Supported patch surfaces:
- OS packages when available (`apt`, `apk`, `yum`, `dnf`)
- `npm`
- `pip`

Current non-goals:
- Runtime families outside Node.js/Python
- Guaranteed remediation for every base image/CVE combination

## High-Level Flow

1. Resolve inputs (image, Dockerfile path, credentials, options)
2. Build source image from Dockerfile or pull source image from registry
3. Run baseline Docker Scout scan
4. Select fixable CVEs by severity
5. Generate patch Dockerfile and patch plan artifacts
6. Build patched image
7. Run post-patch Docker Scout verification
8. Fail if targeted fixable CVEs remain
9. Optionally push verified patched image

## Input Resolution: Where It Reads Dockerfile, Image, and Credentials

### CLI mode (`docker-vuln-patcher` / `patch_image.py`)

Input precedence and source:

| Input | Source | Resolution behavior |
|---|---|---|
| Image | `--image` (required) | Always required target reference |
| Dockerfile | `--dockerfile-path` | If provided, build source image first |
| Build context | `--context-path` | If omitted, defaults to Dockerfile parent folder |
| Build args | repeated `--build-arg KEY=VALUE` | Passed to source image build |
| Docker Hub username | `--dh-user` then env from `--dh-user-env` | `--dh-user` has priority |
| Docker Hub password/token | env from `--dh-password-env` | Used with `docker login --password-stdin` |
| Non-interactive mode | `--non-interactive` | Fails when required credentials are missing |
| Report output folder | `--report-dir` | Defaults to `./vuln_reports` |

Image source behavior:
- If `--dockerfile-path` is set: build source image from local files.
- If `--dockerfile-path` is not set: pull `--image` from registry.

### GitHub Action mode (`qasimnauman/patch-docker-image@v1`)

Action input sources:
- Image/build inputs come from `with:` values in workflow YAML.
- Credentials are typically wired from repository/org secrets.

Recommended secret mapping:
- `dh-user: ${{ secrets.DOCKERHUB_USERNAME }}`
- `dh-password: ${{ secrets.DOCKERHUB_PASSWORD }}`

Dockerfile behavior is identical to CLI:
- `dockerfile-path` set -> build first from workflow workspace
- `dockerfile-path` empty -> pull `image` from registry

## Quick Start

### A) Use as a public GitHub Action (recommended)

```yaml
name: Patch Docker Image

on:
  workflow_dispatch:

jobs:
  patch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Patch and verify image
        id: patch
        uses: qasimnauman/patch-docker-image@v1
        with:
          image: myrepo/myapp:latest
          severities: CRITICAL,HIGH,MEDIUM,LOW
          push: "false"
          non-interactive: "true"
          dh-user: ${{ secrets.DOCKERHUB_USERNAME }}
          dh-password: ${{ secrets.DOCKERHUB_PASSWORD }}

      - name: Output patched tag
        run: echo "Patched image: ${{ steps.patch.outputs.patched_image }}"
```

### B) Use locally via CLI

Install:

```bash
python -m pip install --upgrade pip
pip install .
```

Patch an existing registry image:

```bash
docker-vuln-patcher \
  --image myrepo/myapp:latest \
  --non-interactive \
  --report-dir ./vuln_reports
```

Build from Dockerfile, then patch:

```bash
docker-vuln-patcher \
  --image myrepo/myapp:latest \
  --dockerfile-path ./Dockerfile \
  --context-path . \
  --build-arg APP_ENV=prod \
  --non-interactive \
  --report-dir ./vuln_reports
```

Patch, verify, and push:

```bash
docker-vuln-patcher \
  --image myrepo/myapp:latest \
  --non-interactive \
  --push
```

## CLI Reference

| Flag | Required | Default | Description |
|---|---|---|---|
| `--image` | Yes | none | Target image reference |
| `--dockerfile-path` | No | none | Build source image from Dockerfile |
| `--context-path` | No | Dockerfile parent | Build context for Dockerfile mode |
| `--build-arg` | No | none | Repeatable source-image build args |
| `--patched-suffix` | No | `-patched` | Suffix appended to target image tag |
| `--severities` | No | `CRITICAL,HIGH,MEDIUM,LOW` | Target severities for selection/verification |
| `--dh-user` | No | none | Docker Hub username override |
| `--dh-user-env` | No | `DOCKERHUB_USERNAME` | Username env var key |
| `--dh-password-env` | No | `DOCKERHUB_PASSWORD` | Password/token env var key |
| `--non-interactive` | No | false | Disable credential prompt fallback |
| `--push` | No | false | Push verified patched image |
| `--use-buildx` | No | false | Build patched image with `docker buildx` |
| `--dry-run` | No | false | Skip build/verify/push, generate artifacts only |
| `--report-dir` | No | `./vuln_reports` | Output folder for artifacts |
| `--debug` | No | false | Enable debug logs |

## GitHub Action Reference

Public action:
- `qasimnauman/patch-docker-image@v1`

Primary action file:
- repository root `action.yml`

Backward-compatible internal path:
- `.github/actions/patch-docker-image/action.yml`

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `image` | Yes | none | Target image reference |
| `dockerfile-path` | No | empty | Optional Dockerfile path |
| `context-path` | No | empty | Optional Docker build context |
| `build-args` | No | empty | Newline-separated `KEY=VALUE` build args |
| `severities` | No | `CRITICAL,HIGH,MEDIUM,LOW` | Severity selection |
| `patched-suffix` | No | `-patched` | Patched image suffix |
| `report-dir` | No | `./vuln_reports` | Artifact output folder |
| `dh-user` | No | empty | Docker Hub username |
| `dh-password` | No | empty | Docker Hub password/token |
| `push` | No | `false` | Push verified patched image |
| `dry-run` | No | `false` | Generate only, skip build/verify/push |
| `non-interactive` | No | `true` | Fail if credentials are missing |
| `use-buildx` | No | `false` | Use buildx for patched build |
| `python-version` | No | `3.12` | Python runtime for action job |

### Outputs

| Output | Description |
|---|---|
| `patched_image` | Derived patched image tag |

## Security and Secret Handling

Security behavior:
- Password/token is passed through stdin (`docker login --password-stdin`)
- Password value is not logged by the tool
- Credential variables are configurable by key (`--dh-user-env`, `--dh-password-env`)

Best practices:
- Use short-lived tokens instead of account passwords when possible
- Keep push permissions minimal and scoped
- Do not commit raw vulnerability reports to public repos without review
- Treat generated reports as potentially sensitive operational artifacts

## Artifacts

Default output root:
- `./vuln_reports`

Generated artifacts:
- Baseline scan report: `scout_<safe-image>.json`
- Patch plan: `patch_plan_<safe-image>.json`
- Post-patch scan report: `post_patch_scout_<safe-image>.json`
- Generated Dockerfile: `patches/Dockerfile.<safe-image>.patched`

## Exit Codes

| Exit code | Meaning |
|---|---|
| `0` | Success (or nothing fixable for selected severities) |
| `1` | Invalid configuration/input/auth/runtime error |
| `2` | Safe failure (unsupported runtime, no patchable CVEs, or verification failed) |

## Production Operations Checklist

- Pin action usage to a stable major tag (`@v1`) or commit SHA
- Configure repository/org secrets for Docker Hub credentials
- Start with `dry-run: "true"` on new repos to validate behavior
- Enable push only after successful verification behavior is confirmed
- Keep base images and dependency lockfiles updated regularly
- Monitor release notes and move tags intentionally

## Troubleshooting

### Docker daemon unavailable
- Ensure Docker is installed and daemon is running on the runner/host.

### Docker Scout unavailable
- Ensure Docker Scout plugin is installed and accessible (`docker scout version`).

### Verification fails after patch build
- This is expected in some image/CVE combinations.
- The tool is intentionally strict and fails to avoid false success.
- Review generated reports and patch Dockerfile under report-dir.

### Missing credentials in CI
- Provide `dh-user` and `dh-password` from secrets.
- Keep `non-interactive` enabled for deterministic CI behavior.

## Releasing Action Versions

Release workflow:
- `.github/workflows/release-action-tags.yml`

Recommended tagging model:
- Immutable semantic tag: `v1.0.0`
- Moving major tag: `v1`

Consumer reference:

```yaml
uses: qasimnauman/patch-docker-image@v1
```

## Project Structure

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
LICENSE
```

## License

MIT
