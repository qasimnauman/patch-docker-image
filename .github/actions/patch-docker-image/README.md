# Patch Docker Image Composite Action

Reusable GitHub composite action for running docker-vuln-patcher in any workflow.

## Inputs

- `image` (required): Docker image reference to patch.
- `dockerfile-path`: Optional Dockerfile path to build the source image first.
- `context-path`: Optional build context path for dockerfile-path.
- `build-args`: Optional newline-separated build args (`KEY=VALUE`).
- `severities`: Comma-separated severities, default `CRITICAL,HIGH,MEDIUM,LOW`.
- `patched-suffix`: Patched tag suffix, default `-patched`.
- `report-dir`: Reports directory, default `./vuln_reports`.
- `dh-user`: Docker Hub username.
- `dh-password`: Docker Hub password/token.
- `push`: Push verified image (`true` or `false`).
- `dry-run`: Generate artifacts only (`true` or `false`).
- `non-interactive`: Fail when credentials are missing (`true` or `false`).
- `use-buildx`: Build patched image with buildx (`true` or `false`).
- `python-version`: Python runtime version, default `3.12`.

## Output

- `patched_image`: Derived patched image tag.

## Example (same repo)

```yaml
jobs:
  patch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: patch
        uses: ./.github/actions/patch-docker-image
        with:
          image: myrepo/myapp:latest
          dh-user: ${{ secrets.DOCKERHUB_USERNAME }}
          dh-password: ${{ secrets.DOCKERHUB_PASSWORD }}
          push: "true"
```

## Example (other repo)

```yaml
jobs:
  patch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: patch
        uses: your-org/docker-vuln-patcher/.github/actions/patch-docker-image@v0.1.0
        with:
          image: myrepo/myapp:latest
          dh-user: ${{ secrets.DOCKERHUB_USERNAME }}
          dh-password: ${{ secrets.DOCKERHUB_PASSWORD }}
```

Pin to a release tag or full commit SHA for production use.
