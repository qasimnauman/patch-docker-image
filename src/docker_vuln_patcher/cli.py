#!/usr/bin/env python3
"""
Production-oriented Docker image vulnerability patcher.

Current scope:
- Supported runtime families: Node.js and Python images
- Supports scanning an existing image OR building one from a Dockerfile first
- Generates a patch Dockerfile artifact
- Verifies the patched image with a post-build Docker Scout scan before final success
"""

from __future__ import annotations

import argparse
import getpass
import json
import shutil
import logging
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("docker_vuln_patcher")


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
DEFAULT_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

SEV_COLOR = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[0;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[0;33m",
    "UNKNOWN": "\033[0;37m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


@dataclass
class CVE:
    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    package_type: str = ""
    description: str = ""

    @property
    def is_fixable(self) -> bool:
        return bool(self.fixed_version and self.fixed_version.strip())


@dataclass
class ScanReport:
    image: str
    cves: list[CVE] = field(default_factory=list)

    def fixable(self, severities: list[str]) -> list[CVE]:
        sev_set = {s.upper() for s in severities}
        return [c for c in self.cves if c.is_fixable and c.severity.upper() in sev_set]

    def by_severity(self) -> dict[str, list[CVE]]:
        out: dict[str, list[CVE]] = defaultdict(list)
        for c in self.cves:
            out[c.severity.upper()].append(c)
        return out


def safe_name_for_path(image: str) -> str:
    return image.replace("/", "_").replace(":", "_").replace("@", "_")


def parse_image_reference(image: str) -> tuple[str, str]:
    """
    Parse image reference into repository/name and tag.

    Handles registry ports correctly. Digest references are intentionally rejected
    for patched-tag derivation.
    """
    ref = (image or "").strip()
    if not ref:
        raise ValueError("Image reference is empty.")
    if "@" in ref:
        raise ValueError(
            "Digest references are not supported for patch tagging. Use an explicit tag instead."
        )

    last_slash = ref.rfind("/")
    last_colon = ref.rfind(":")
    has_tag = last_colon > last_slash

    if has_tag:
        repository = ref[:last_colon]
        tag = ref[last_colon + 1 :]
    else:
        repository = ref
        tag = "latest"

    if not repository:
        raise ValueError(f"Invalid image reference: '{image}'")
    if not tag:
        raise ValueError(f"Invalid image tag in reference: '{image}'")

    return repository, tag


def derive_patched_tag(image: str, suffix: str) -> str:
    repository, tag = parse_image_reference(image)
    return f"{repository}:{tag}{suffix}"


def normalize_severity(value: str) -> str:
    sev = (value or "UNKNOWN").strip().upper()
    if sev not in SEVERITY_ORDER:
        return "UNKNOWN"
    return sev


def run_command(
    cmd: list[str],
    *,
    capture_output: bool = False,
    input_text: Optional[str] = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=capture_output,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        input=input_text,
    )


def dockerhub_login(
    username: Optional[str],
    *,
    password_env: str,
    non_interactive: bool,
) -> None:
    if not username:
        log.info("No Docker Hub username provided; using existing Docker session.")
        return

    password = os.getenv(password_env)
    if password is None:
        if non_interactive or not sys.stdin.isatty():
            log.error(
                "Docker Hub username was provided but password was not found in env '%s'.",
                password_env,
            )
            sys.exit(1)
        password = getpass.getpass(f"Docker Hub password for {username}: ")

    log.info("Logging into Docker Hub as '%s' with password-stdin.", username)
    result = run_command(
        ["docker", "login", "--username", username, "--password-stdin"],
        capture_output=True,
        input_text=password,
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        log.error("Docker Hub login failed. %s", stderr)
        sys.exit(1)
    log.info("Docker Hub login successful.")


def pull_image(image: str) -> None:
    log.info("Pulling image: %s", image)
    result = run_command(["docker", "pull", image])
    if result.returncode != 0:
        log.error("Failed to pull image '%s'.", image)
        sys.exit(1)


def build_image_from_dockerfile(
    image: str,
    dockerfile_path: Path,
    context_path: Path,
    build_args: list[str],
) -> None:
    if not dockerfile_path.exists():
        log.error("Dockerfile not found: %s", dockerfile_path)
        sys.exit(1)
    if not context_path.exists():
        log.error("Build context path does not exist: %s", context_path)
        sys.exit(1)

    cmd = ["docker", "build", "-f", str(dockerfile_path), "-t", image]
    for arg in build_args:
        cmd.extend(["--build-arg", arg])
    cmd.append(str(context_path))

    log.info(
        "Building source image '%s' from Dockerfile '%s' (%d build args).",
        image,
        dockerfile_path,
        len(build_args),
    )
    result = run_command(cmd)
    if result.returncode != 0:
        log.error("Source image build failed (exit %d).", result.returncode)
        sys.exit(result.returncode)


def run_docker_scout(image: str, report_dir: Path, prefix: str = "scout") -> Path:
    """
    Run Docker Scout CVE scan and save JSON output.

    Tries multiple invocation strategies in priority order so that the tool
    works across Docker Scout versions and both plugin/standalone installs:

      1. --format json --output <file>   (best: avoids stdout parsing entirely)
      2. --format json  (capture stdout)
      3. Repeat 1-2 with plain image ref instead of local:// (older Scout compat)

    The 'gitlab' format is intentionally omitted — it is not a standard Docker
    Scout format and is not reliably available across versions.
    """
    report_dir.mkdir(parents=True, exist_ok=True)
    safe_name = safe_name_for_path(image)
    report_path = report_dir / f"{prefix}_{safe_name}.json"

    log.info("Running Docker Scout on: %s", image)

    def extract_json_blob(text: str) -> str:
        text = (text or "").strip()
        if not text:
            return ""
        json_start = next((i for i, ch in enumerate(text) if ch in ("{", "[")), -1)
        if json_start == -1:
            return ""
        return text[json_start:]

    def try_parse_json(raw: str) -> str:
        """Return raw if it parses as JSON, else ''."""
        blob = extract_json_blob(raw)
        if not blob:
            return ""
        try:
            json.loads(blob)
            return blob
        except json.JSONDecodeError:
            return ""

    scout_cmd_variants: list[list[str]] = []
    if shutil.which("docker"):
        scout_cmd_variants.append(["docker", "scout", "cves"])
    if shutil.which("docker-scout"):
        scout_cmd_variants.append(["docker-scout", "cves"])

    if not scout_cmd_variants:
        log.error("Neither 'docker scout' nor 'docker-scout' is available on PATH.")
        sys.exit(1)

    # Try local:// first (explicit local daemon lookup), then plain tag as fallback
    # for older Scout versions that do not understand the local:// scheme.
    image_refs = [f"local://{image}", image]

    raw_output = ""
    attempt_errors: list[str] = []
    attempts_desc: list[str] = []

    outer_break = False
    for image_ref in image_refs:
        if outer_break:
            break
        for cmd_prefix in scout_cmd_variants:
            if outer_break:
                break

            # ── Strategy 1: write directly to file (avoids stdout buffering issues) ──
            tmp_out = report_dir / f"{prefix}_{safe_name}_raw.json"
            attempt_key = f"{' '.join(cmd_prefix)} {image_ref} --format json --output"
            attempts_desc.append(attempt_key)
            r = run_command(
                [*cmd_prefix, image_ref, "--format", "json", "--output", str(tmp_out)],
                capture_output=True,
            )
            log.debug(
                "Scout attempt [exit=%d] %s | stderr=%r | stdout=%r",
                r.returncode,
                attempt_key,
                (r.stderr or "").strip()[:400],
                (r.stdout or "").strip()[:200],
            )
            if tmp_out.exists() and tmp_out.stat().st_size > 0:
                blob = try_parse_json(tmp_out.read_text(encoding="utf-8", errors="replace"))
                if blob:
                    raw_output = blob
                    outer_break = True
                    break
            err1 = (r.stderr or "").strip()
            if err1 or r.returncode != 0:
                attempt_errors.append(
                    f"{attempt_key} [exit={r.returncode}]: {err1[:300] or '(no stderr)'}"
                )

            # ── Strategy 2: capture stdout ──
            attempt_key2 = f"{' '.join(cmd_prefix)} {image_ref} --format json (stdout)"
            attempts_desc.append(attempt_key2)
            r2 = run_command(
                [*cmd_prefix, image_ref, "--format", "json"],
                capture_output=True,
            )
            log.debug(
                "Scout attempt [exit=%d] %s | stderr=%r | stdout=%r",
                r2.returncode,
                attempt_key2,
                (r2.stderr or "").strip()[:400],
                (r2.stdout or "").strip()[:200],
            )
            for stream in (r2.stdout, r2.stderr):
                blob = try_parse_json(stream or "")
                if blob:
                    raw_output = blob
                    outer_break = True
                    break
            if outer_break:
                break
            err2 = (r2.stderr or "").strip()
            if err2 or r2.returncode != 0:
                attempt_errors.append(
                    f"{attempt_key2} [exit={r2.returncode}]: {err2[:300] or '(no stderr)'}"
                )

    if not raw_output:
        log.error(
            "Docker Scout returned no parseable JSON output. Attempted: %s",
            "; ".join(attempts_desc),
        )
        if attempt_errors:
            log.error("Scout errors: %s", " | ".join(attempt_errors[:6]))
        sys.exit(1)

    report_path.write_text(raw_output, encoding="utf-8")
    log.info("Scout report saved: %s", report_path)
    return report_path


def parse_scout_report(report_path: Path, image: str) -> ScanReport:
    log.info("Parsing Scout report: %s", report_path)
    with report_path.open(encoding="utf-8") as f:
        data = json.load(f)

    cves: list[CVE] = []

    def package_from_purl(raw_pkg: str) -> str:
        if not raw_pkg:
            return ""
        without_scheme = raw_pkg.split("pkg:", 1)[-1]
        name_part = without_scheme.split("@", 1)[0]
        if "/" in name_part:
            return name_part.split("/", 1)[-1]
        return name_part

    def package_type_from_purl(raw_pkg: str) -> str:
        if not raw_pkg:
            return ""
        without_scheme = raw_pkg.split("pkg:", 1)[-1]
        return without_scheme.split("/", 1)[0].lower().strip()

    def fixed_from_solution(solution: str) -> str:
        if not solution:
            return ""
        match = re.search(r"\bto\s+([^\s,;]+)", solution)
        return match.group(1).strip() if match else ""

    if "packages" in data:
        for pkg in data.get("packages", []):
            pkg_name = pkg.get("name", "")
            pkg_version = pkg.get("version", "")
            for vuln in pkg.get("vulnerabilities", []):
                cves.append(
                    CVE(
                        vuln_id=vuln.get("id", ""),
                        pkg_name=pkg_name,
                        installed_version=pkg_version,
                        fixed_version=vuln.get("fixed_version", ""),
                        severity=normalize_severity(vuln.get("severity", "UNKNOWN")),
                        package_type=(vuln.get("package_type", pkg.get("type", "")) or "").lower(),
                        description=(vuln.get("description", "") or "")[:120],
                    )
                )
    elif "vulnerabilities" in data:
        for vuln in data.get("vulnerabilities", []):
            location = vuln.get("location", {}) or {}
            dep = location.get("dependency", {}) or {}
            pkg = dep.get("package", {}) or {}

            package_name = vuln.get("package", vuln.get("pkg_name", ""))
            if not package_name and pkg.get("name"):
                package_name = package_from_purl(pkg.get("name", ""))

            package_type = (vuln.get("package_type", "") or pkg.get("type", "")).lower().strip()
            if not package_type and pkg.get("name"):
                package_type = package_type_from_purl(pkg.get("name", ""))

            fixed_version = vuln.get("fixed_version", "")
            if not fixed_version:
                fixed_version = fixed_from_solution(vuln.get("solution", ""))

            cves.append(
                CVE(
                    vuln_id=vuln.get("id", vuln.get("cve_id", "")),
                    pkg_name=package_name,
                    installed_version=vuln.get("version", dep.get("version", "")),
                    fixed_version=fixed_version,
                    severity=normalize_severity(vuln.get("severity", "UNKNOWN")),
                    package_type=package_type,
                    description=(vuln.get("description", "") or "")[:120],
                )
            )
    else:
        log.warning("Unrecognized Scout JSON schema. No CVEs extracted.")

    log.info("Parsed %d CVE(s).", len(cves))
    return ScanReport(image=image, cves=cves)


def print_report(report: ScanReport, fixable: list[CVE], severities: list[str], title: str) -> None:
    by_sev = report.by_severity()

    print(f"\n{BOLD}{'=' * 68}{RESET}")
    print(f"{BOLD}  {title}: {report.image}{RESET}")
    print(f"{BOLD}{'=' * 68}{RESET}")

    for sev in SEVERITY_ORDER:
        bucket = by_sev.get(sev, [])
        if not bucket:
            continue
        color = SEV_COLOR.get(sev, "")
        fixable_n = sum(1 for c in bucket if c.is_fixable)
        print(f"  {color}{sev:<10}{RESET}  total={len(bucket):<5} fixable={fixable_n}")

    print(f"\n  Total CVEs      : {len(report.cves)}")
    print(f"  Auto-fixable    : {len(fixable)}")
    print(f"  Severities      : {', '.join(severities)}")

    if fixable:
        print(f"\n{BOLD}{'-' * 68}{RESET}")
        print("  CVEs selected for this pass:")
        print(f"{'-' * 68}")
        for cve in sorted(fixable, key=lambda c: SEVERITY_ORDER.index(normalize_severity(c.severity))):
            color = SEV_COLOR.get(normalize_severity(cve.severity), "")
            print(
                f"  [{color}{normalize_severity(cve.severity):<8}{RESET}] "
                f"{cve.vuln_id:<20} "
                f"{cve.pkg_name} "
                f"{cve.installed_version} -> {cve.fixed_version}"
            )
    print(f"{BOLD}{'=' * 68}{RESET}\n")


def save_patch_plan(cves: list[CVE], report_dir: Path, image: str) -> Path:
    out = report_dir / f"patch_plan_{safe_name_for_path(image)}.json"
    payload = [
        {
            "cve_id": c.vuln_id,
            "package": c.pkg_name,
            "from": c.installed_version,
            "to": c.fixed_version,
            "severity": normalize_severity(c.severity),
            "package_type": (c.package_type or "unknown"),
        }
        for c in cves
    ]
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    log.info("Patch plan saved: %s", out)
    return out


def write_generated_dockerfile(report_dir: Path, image: str, dockerfile: str) -> Path:
    patch_dir = report_dir / "patches"
    patch_dir.mkdir(parents=True, exist_ok=True)
    target = patch_dir / f"Dockerfile.{safe_name_for_path(image)}.patched"
    target.write_text(dockerfile, encoding="utf-8")
    log.info("Generated patch Dockerfile: %s", target)
    return target


def command_exists_in_image(image: str, binary: str) -> bool:
    shell_probes = ["sh", "/bin/sh"]
    for shell in shell_probes:
        result = run_command(
            ["docker", "run", "--rm", "--entrypoint", shell, image, "-c", f"command -v {binary} >/dev/null 2>&1"],
            capture_output=True,
        )
        if result.returncode == 0:
            return True

    direct_probes = ["--version", "-v", "--help"]
    for arg in direct_probes:
        result = run_command(
            ["docker", "run", "--rm", "--entrypoint", binary, image, arg],
            capture_output=True,
        )
        if result.returncode == 0:
            return True

    return False


def detect_package_manager(image: str) -> Optional[str]:
    checks = [
        ("apt-get", "apt"),
        ("apk", "apk"),
        ("dnf", "dnf"),
        ("yum", "yum"),
    ]
    for binary, name in checks:
        if command_exists_in_image(image, binary):
            log.info("Detected OS package manager: %s", name)
            return name
    log.warning("No OS package manager detected in image.")
    return None


def detect_patch_capabilities(image: str, os_pkg_manager: Optional[str]) -> dict[str, str]:
    capabilities: dict[str, str] = {}
    if os_pkg_manager:
        capabilities[os_pkg_manager] = os_pkg_manager

    if command_exists_in_image(image, "npm"):
        capabilities["npm"] = "npm"
    if command_exists_in_image(image, "yarn"):
        capabilities["yarn"] = "yarn"
    if command_exists_in_image(image, "pnpm"):
        capabilities["pnpm"] = "pnpm"

    if command_exists_in_image(image, "pip3"):
        capabilities["pip"] = "pip3"
    elif command_exists_in_image(image, "pip"):
        capabilities["pip"] = "pip"
    elif command_exists_in_image(image, "python3"):
        probe = run_command(
            ["docker", "run", "--rm", image, "python3", "-m", "pip", "--version"],
            capture_output=True,
        )
        if probe.returncode == 0:
            capabilities["pip"] = "python3 -m pip"
    elif command_exists_in_image(image, "python"):
        probe = run_command(
            ["docker", "run", "--rm", image, "python", "-m", "pip", "--version"],
            capture_output=True,
        )
        if probe.returncode == 0:
            capabilities["pip"] = "python -m pip"

    if capabilities:
        log.info("Detected patch capabilities: %s", ", ".join(sorted(capabilities.keys())))
    else:
        log.warning("No patch capabilities detected.")

    return capabilities


def ensure_supported_runtime(capabilities: dict[str, str]) -> None:
    has_node = any(k in capabilities for k in ("npm", "yarn", "pnpm"))
    has_python = "pip" in capabilities
    if not has_node and not has_python:
        log.error(
            "Unsupported image runtime for this release. "
            "Only Node.js and Python based images are currently supported."
        )
        sys.exit(2)


def select_latest_fixed_versions(cves: list[CVE]) -> dict[str, str]:
    by_package: dict[str, str] = {}

    def version_key(raw: str) -> tuple:
        chunks = re.split(r"[^0-9A-Za-z]+", raw or "")
        key: list[tuple[int, object]] = []
        for chunk in chunks:
            if not chunk:
                continue
            if chunk.isdigit():
                key.append((0, int(chunk)))
            else:
                key.append((1, chunk.lower()))
        return tuple(key)

    for cve in cves:
        pkg = (cve.pkg_name or "").strip()
        candidate = (cve.fixed_version or "").strip()
        if not pkg or not candidate:
            continue
        current = by_package.get(pkg)
        if current is None or version_key(candidate) > version_key(current):
            by_package[pkg] = candidate
    return by_package


def build_os_upgrade_run(pkg_manager: str, packages: list[str]) -> list[str]:
    def normalize_os_package_name(name: str) -> str:
        raw = (name or "").strip()
        if not raw:
            return ""
        if "/" in raw:
            raw = raw.split("/", 1)[-1]
        return raw

    normalized = sorted({normalize_os_package_name(p) for p in packages if normalize_os_package_name(p)})
    if not normalized:
        return []
    pkg_list = " ".join(normalized)

    if pkg_manager == "apt":
        return [
            "RUN apt-get update -y && \\",
            f"    apt-get install --only-upgrade -y {pkg_list} && \\",
            "    apt-get clean && rm -rf /var/lib/apt/lists/*",
        ]
    if pkg_manager == "apk":
        return [f"RUN apk update && apk upgrade --no-cache {pkg_list}"]
    if pkg_manager in ("yum", "dnf"):
        return [f"RUN {pkg_manager} update -y {pkg_list} && {pkg_manager} clean all"]
    return [
        "# Unsupported OS package manager for auto-remediation",
        f"# Packages needing upgrade: {pkg_list}",
    ]


def build_node_upgrade_run(packages_to_version: dict[str, str], managers: list[str]) -> list[str]:
    """
    Generate RUN instruction for Node.js package upgrades.
    
    Dynamically finds package.json in the filesystem (no hardcoded paths).
    Tries app-level install first, then falls back to global.
    """
    specs = [f"{name}@{version}" for name, version in sorted(packages_to_version.items()) if version]
    if not specs:
        return []
    if not managers:
        return []

    joined = " ".join(specs)
    app_install_steps = []
    for mgr in managers:
        if mgr == "npm":
            app_install_steps.append(f"if command -v npm >/dev/null 2>&1; then npm install --no-audit --no-fund {joined}; exit 0; fi; ")
        elif mgr == "yarn":
            app_install_steps.append(f"if command -v yarn >/dev/null 2>&1; then yarn add {joined}; exit 0; fi; ")
        elif mgr == "pnpm":
            app_install_steps.append(f"if command -v pnpm >/dev/null 2>&1; then pnpm add {joined}; exit 0; fi; ")
    manager_chain = "".join(app_install_steps)

    return [
        "RUN set -eu; \\",
        "    found=0; \\",
        "    app_dir=$(find / -maxdepth 3 -name package.json -type f 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true); \\",
        "    if [ -n \"$app_dir\" ] && [ -f \"$app_dir/package.json\" ]; then \\",
        "      cd \"$app_dir\"; \\",
        f"      {manager_chain} \\",
        "      echo 'No Node package manager found in image.'; exit 1; \\",
        "    else \\",
        "      if command -v npm >/dev/null 2>&1; then npm install -g --no-audit --no-fund " + joined + "; exit 0; fi; \\",
        "      if command -v yarn >/dev/null 2>&1; then yarn global add " + joined + "; exit 0; fi; \\",
        "      if command -v pnpm >/dev/null 2>&1; then pnpm add -g " + joined + "; exit 0; fi; \\",
        "      echo 'No Node package manager found in image.'; exit 1; \\",
        "    fi",
    ]


def build_pip_upgrade_run(pip_cmd: str, packages_to_version: dict[str, str]) -> list[str]:
    specs = [f"{name}=={version}" for name, version in sorted(packages_to_version.items()) if version]
    if not specs:
        return []
    return [f"RUN {pip_cmd} install --no-cache-dir --upgrade {' '.join(specs)}"]


def select_patchable_cves(
    os_pkg_manager: Optional[str],
    capabilities: dict[str, str],
    fixable: list[CVE],
) -> tuple[dict[str, list[CVE]], list[CVE]]:
    patchable_by_manager: dict[str, list[CVE]] = defaultdict(list)
    skipped: list[CVE] = []

    def manager_for_pkg_type(pkg_type: str) -> Optional[str]:
        pt = (pkg_type or "").lower().strip()
        if pt in {"", "deb", "apk", "rpm"}:
            return os_pkg_manager
        if pt == "npm":
            return "npm"
        if pt in {"pypi", "python"}:
            return "pip"
        return None

    for cve in fixable:
        manager = manager_for_pkg_type(cve.package_type)
        if not manager or manager not in capabilities or not cve.pkg_name:
            skipped.append(cve)
            continue
        patchable_by_manager[manager].append(cve)

    return patchable_by_manager, skipped


def generate_dockerfile(
    base_image: str,
    os_pkg_manager: Optional[str],
    capabilities: dict[str, str],
    fixable: list[CVE],
) -> tuple[str, list[CVE], list[CVE]]:
    patchable_by_manager, skipped = select_patchable_cves(os_pkg_manager, capabilities, fixable)
    patchable = [c for group in patchable_by_manager.values() for c in group]

    os_group_key = os_pkg_manager or ""
    os_packages = sorted({c.pkg_name for c in patchable_by_manager.get(os_group_key, []) if c.pkg_name})
    npm_versions = select_latest_fixed_versions(patchable_by_manager.get("npm", []))
    pip_versions = select_latest_fixed_versions(patchable_by_manager.get("pip", []))

    run_lines: list[str] = []
    if os_pkg_manager and os_packages:
        run_lines.extend(build_os_upgrade_run(os_pkg_manager, os_packages))
    if "npm" in patchable_by_manager:
        managers = [m for m in ("pnpm", "yarn", "npm") if m in capabilities]
        run_lines.extend(build_node_upgrade_run(npm_versions, managers))
    if "pip" in patchable_by_manager:
        run_lines.extend(build_pip_upgrade_run(capabilities["pip"], pip_versions))

    if not run_lines:
        run_lines = [
            "# No compatible CVEs found for automated patching.",
            "# Tip: update base image and app dependencies manually.",
        ]

    skipped_pairs = sorted({(c.pkg_name, c.package_type or "unknown") for c in skipped})
    skipped_summary = ", ".join(f"{name}({ptype})" for name, ptype in skipped_pairs[:8])
    if len(skipped_pairs) > 8:
        skipped_summary += ", ..."

    lines = [
        "# Auto-generated by docker_vuln_patcher",
        f"# Base image          : {base_image}",
        f"# Patches requested   : {len(fixable)} CVE(s)",
        f"# OS patchable CVEs   : {len(patchable_by_manager.get(os_group_key, []))}",
        f"# NPM patchable CVEs  : {len(patchable_by_manager.get('npm', []))}",
        f"# PIP patchable CVEs  : {len(patchable_by_manager.get('pip', []))}",
        f"# Skipped CVEs        : {len(skipped)}",
        "",
        f"FROM {base_image}",
        "",
    ]

    if skipped_summary:
        lines.extend([f"# Skipped packages: {skipped_summary}", ""])

    lines.extend(["# Vulnerability patches"] + run_lines + ["", "# End patches", ""])
    return "\n".join(lines), patchable, skipped


def build_patched_image(dockerfile_path: Path, patched_tag: str, use_buildx: bool) -> None:
    context = dockerfile_path.parent
    if use_buildx:
        cmd = [
            "docker",
            "buildx",
            "build",
            "--load",
            "-f",
            str(dockerfile_path),
            "-t",
            patched_tag,
            str(context),
        ]
    else:
        cmd = ["docker", "build", "-f", str(dockerfile_path), "-t", patched_tag, str(context)]

    log.info("Building patched image: %s", patched_tag)
    result = run_command(cmd)
    if result.returncode != 0:
        log.error("Patched image build failed (exit %d).", result.returncode)
        sys.exit(result.returncode)


def push_image(patched_tag: str) -> None:
    log.info("Pushing patched image: %s", patched_tag)
    result = run_command(["docker", "push", patched_tag])
    if result.returncode != 0:
        log.error("docker push failed (exit %d).", result.returncode)
        sys.exit(result.returncode)


def print_summary(
    original_image: str,
    patched_tag: str,
    generated_dockerfile_path: Path,
    requested_fixes: int,
    attempted_fixes: int,
    remaining_fixes: int,
    pushed: bool,
) -> None:
    print(f"\n{BOLD}{'=' * 68}{RESET}")
    print(f"{BOLD}  Pipeline Complete{RESET}")
    print(f"{BOLD}{'=' * 68}{RESET}")
    print(f"  Original image      : {original_image}")
    print(f"  Patched image       : \033[0;32m{patched_tag}{RESET}")
    print(f"  Patch Dockerfile    : {generated_dockerfile_path}")
    print(f"  Requested CVE fixes : {requested_fixes}")
    print(f"  Attempted CVE fixes : {attempted_fixes}")
    print(f"  Remaining fixable   : {remaining_fixes}")
    print(f"  Pushed to registry  : {'yes' if pushed else 'no'}")
    print(f"{BOLD}{'=' * 68}{RESET}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan and patch Docker image vulnerabilities (Node.js/Python images), "
            "then verify with a post-patch Scout scan."
        )
    )
    parser.add_argument(
        "--image",
        required=True,
        help="Target image reference (e.g. myrepo/myapp:latest)",
    )
    parser.add_argument(
        "--dockerfile-path",
        default=None,
        help=(
            "Optional Dockerfile path to build the source image before scanning. "
            "If omitted, the tool pulls --image from registry."
        ),
    )
    parser.add_argument(
        "--context-path",
        default=None,
        help="Optional build context path used with --dockerfile-path (defaults to Dockerfile folder).",
    )
    parser.add_argument(
        "--build-arg",
        action="append",
        default=[],
        help="Build arg for source image build (repeatable, format KEY=VALUE).",
    )
    parser.add_argument(
        "--patched-suffix",
        default="-patched",
        help="Suffix appended to source image tag for patched output image.",
    )
    parser.add_argument(
        "--severities",
        default=",".join(DEFAULT_SEVERITIES),
        help="Comma-separated severities to target (default: CRITICAL,HIGH,MEDIUM,LOW).",
    )
    parser.add_argument(
        "--dh-user",
        default=None,
        help="Docker Hub username. If omitted, falls back to env from --dh-user-env.",
    )
    parser.add_argument(
        "--dh-user-env",
        default="DOCKERHUB_USERNAME",
        help="Environment variable used for Docker Hub username.",
    )
    parser.add_argument(
        "--dh-password-env",
        default="DOCKERHUB_PASSWORD",
        help="Environment variable used for Docker Hub password (used with --password-stdin).",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Fail instead of prompting for password when env credential is missing.",
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help="Push verified patched image to registry.",
    )
    parser.add_argument(
        "--use-buildx",
        action="store_true",
        help="Use docker buildx for patched image build (with --load).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate patch artifacts only. Build/push/verification are skipped.",
    )
    parser.add_argument(
        "--report-dir",
        default="./vuln_reports",
        help="Directory for scout reports, patch plan, and generated Dockerfile.",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument(
        "--image-output-file",
        default=None,
        help=(
            "Optional file path where the final patched image tag is written on success. "
            "Used by the GitHub Action to surface the 'patched_image' output."
        ),
    )
    return parser.parse_args()


def _write_image_output(path: Optional[str], tag: str) -> None:
    """Write the final patched image tag to a file for action output capture."""
    if not path:
        return
    try:
        Path(path).write_text(tag, encoding="utf-8")
        log.debug("Wrote patched image tag to %s: %s", path, tag)
    except OSError as exc:
        log.warning("Could not write image output file '%s': %s", path, exc)


def main() -> int:
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    severities = [normalize_severity(s) for s in args.severities.split(",") if s.strip()]
    severities = [s for s in severities if s in SEVERITY_ORDER]
    if not severities:
        log.error("No valid severities provided.")
        return 1

    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    try:
        patched_tag = derive_patched_tag(args.image, args.patched_suffix)
    except ValueError as exc:
        log.error(str(exc))
        return 1

    print(f"\n{BOLD}Docker Vulnerability Patcher (Node.js/Python scope){RESET}\n")

    username = args.dh_user or os.getenv(args.dh_user_env)
    dockerhub_login(
        username,
        password_env=args.dh_password_env,
        non_interactive=args.non_interactive,
    )

    if args.dockerfile_path:
        dockerfile_path = Path(args.dockerfile_path)
        context_path = Path(args.context_path) if args.context_path else dockerfile_path.parent
        build_image_from_dockerfile(args.image, dockerfile_path, context_path, args.build_arg)
    else:
        pull_image(args.image)

    baseline_report_path = run_docker_scout(args.image, report_dir, prefix="scout")
    baseline_scan = parse_scout_report(baseline_report_path, args.image)
    baseline_fixable = baseline_scan.fixable(severities)
    print_report(baseline_scan, baseline_fixable, severities, title="Baseline Vulnerability Report")

    if not baseline_fixable:
        log.info("No fixable CVEs found for selected severities.")
        _write_image_output(args.image_output_file, args.image)
        return 0

    save_patch_plan(baseline_fixable, report_dir, args.image)

    os_pkg_manager = detect_package_manager(args.image)
    capabilities = detect_patch_capabilities(args.image, os_pkg_manager)
    ensure_supported_runtime(capabilities)

    # ============================================================================
    # ITERATIVE PATCHING LOOP: scan -> patch -> verify -> repeat until zero CVEs
    # ============================================================================
    MAX_ITERATIONS = 5
    current_image = args.image
    current_fixable = baseline_fixable
    iteration = 0
    total_patches_applied = 0
    generated_dockerfile_path = None
    patched_tag = None
    final_scan = None
    remaining_fixable = current_fixable

    while iteration < MAX_ITERATIONS and current_fixable:
        iteration += 1
        log.info(
            "=== PATCHING ITERATION %d/%d (%d fixable CVE(s) to address) ===",
            iteration,
            MAX_ITERATIONS,
            len(current_fixable),
        )

        # Generate patch Dockerfile based on current fixable CVEs
        generated_dockerfile, patchable_cves, skipped_cves = generate_dockerfile(
            current_image,
            os_pkg_manager,
            capabilities,
            current_fixable,
        )
        generated_dockerfile_path = write_generated_dockerfile(
            report_dir / f"iteration_{iteration}", current_image, generated_dockerfile
        )

        if skipped_cves:
            skipped_types = sorted({(c.package_type or "unknown") for c in skipped_cves})
            log.warning(
                "Skipped %d CVE(s) due to unsupported package manager/type: %s",
                len(skipped_cves),
                ", ".join(skipped_types),
            )

        if args.dry_run:
            print(f"\n{BOLD}Generated Dockerfile (dry-run, iteration {iteration}): {generated_dockerfile_path}{RESET}\n")
            print(generated_dockerfile)
            log.info("Dry-run complete.")
            _write_image_output(
                args.image_output_file,
                derive_patched_tag(args.image, args.patched_suffix),
            )
            return 0

        if not patchable_cves:
            log.error(
                "Iteration %d: No patchable CVEs found. Cannot proceed with this pass.",
                iteration,
            )
            break

        total_patches_applied += len(patchable_cves)

        # Build patched image with iteration suffix
        iteration_patched_tag = derive_patched_tag(current_image, f"{args.patched_suffix}-iter{iteration}")
        build_patched_image(generated_dockerfile_path, iteration_patched_tag, use_buildx=args.use_buildx)

        # Scan patched image
        verification_report_path = run_docker_scout(
            iteration_patched_tag, report_dir / f"iteration_{iteration}", prefix="post_patch_scout"
        )
        verification_scan = parse_scout_report(verification_report_path, iteration_patched_tag)
        remaining_fixable = verification_scan.fixable(severities)

        print_report(
            verification_scan,
            remaining_fixable,
            severities,
            title=f"Post-Patch Verification Report (Iteration {iteration})",
        )

        if not remaining_fixable:
            # SUCCESS: All CVEs fixed
            log.info("Iteration %d: ✓ All fixable CVEs resolved!", iteration)
            patched_tag = iteration_patched_tag
            final_scan = verification_scan
            break
        else:
            # More CVEs remain; prepare for next iteration
            log.warning(
                "Iteration %d: %d fixable CVE(s) remain. Looping for next pass...",
                iteration,
                len(remaining_fixable),
            )
            current_image = iteration_patched_tag
            current_fixable = remaining_fixable

    # Post-loop: check if we exited due to success or max iterations
    if remaining_fixable:
        if verification_scan:
            print_report(
                verification_scan,
                remaining_fixable,
                severities,
                title="Final Verification Report (FAILED - CVEs Still Present)",
            )
        log.error(
            "Max iterations (%d) reached or no more patchable CVEs, but %d fixable CVE(s) remain. Failing safely.",
            MAX_ITERATIONS,
            len(remaining_fixable),
        )
        return 2

    # SUCCESS PATH: remaining_fixable is empty
    if final_scan:
        print_report(
            final_scan,
            [],
            severities,
            title="✓ Final Verification Report (ZERO VULNERABILITIES - SAFE TO PUSH)",
        )

    if args.push and patched_tag:
        push_image(patched_tag)

    print_summary(
        original_image=args.image,
        patched_tag=patched_tag or args.image,
        generated_dockerfile_path=generated_dockerfile_path,
        requested_fixes=len(baseline_fixable),
        attempted_fixes=total_patches_applied,
        remaining_fixes=0,
        pushed=args.push and patched_tag is not None,
    )
    _write_image_output(args.image_output_file, patched_tag or args.image)
    return 0


if __name__ == "__main__":
    sys.exit(main())
