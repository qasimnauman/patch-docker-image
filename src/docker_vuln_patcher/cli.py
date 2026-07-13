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

    # Format priority: sarif is a stable, always-present JSON format across Scout
    # versions.  json was removed/renamed in Scout v1.22+, so try it second.
    # cyclonedx is a further fallback — also always JSON.
    candidate_formats = ["sarif", "json", "cyclonedx"]

    # Try local:// first (explicit local daemon lookup), then plain tag as fallback
    # for older Scout versions that do not understand the local:// scheme.
    image_refs = [f"local://{image}", image]

    raw_output = ""
    detected_format = ""
    attempt_errors: list[str] = []
    attempts_desc: list[str] = []

    found = False
    for fmt in candidate_formats:
        if found:
            break
        for image_ref in image_refs:
            if found:
                break
            for cmd_prefix in scout_cmd_variants:
                if found:
                    break
                cmd_label = " ".join(cmd_prefix)

                # ── Strategy A: write to file (avoids stdout buffering issues) ──
                tmp_out = report_dir / f"{prefix}_{safe_name}_{fmt}_raw.json"
                key_a = f"{cmd_label} {image_ref} --format {fmt} --output"
                attempts_desc.append(key_a)
                r = run_command(
                    [*cmd_prefix, image_ref, "--format", fmt, "--output", str(tmp_out)],
                    capture_output=True,
                )
                log.debug(
                    "Scout [exit=%d] %s | stderr=%r | stdout=%r",
                    r.returncode, key_a,
                    (r.stderr or "").strip()[:400],
                    (r.stdout or "").strip()[:200],
                )
                if tmp_out.exists() and tmp_out.stat().st_size > 0:
                    blob = try_parse_json(tmp_out.read_text(encoding="utf-8", errors="replace"))
                    if blob:
                        raw_output = blob
                        detected_format = fmt
                        found = True
                        break
                err = (r.stderr or "").strip()
                if err or r.returncode != 0:
                    attempt_errors.append(
                        f"{key_a} [exit={r.returncode}]: {err[:300] or '(no stderr)'}"
                    )

                # ── Strategy B: capture stdout ──
                key_b = f"{cmd_label} {image_ref} --format {fmt} (stdout)"
                attempts_desc.append(key_b)
                r2 = run_command(
                    [*cmd_prefix, image_ref, "--format", fmt],
                    capture_output=True,
                )
                log.debug(
                    "Scout [exit=%d] %s | stderr=%r | stdout=%r",
                    r2.returncode, key_b,
                    (r2.stderr or "").strip()[:400],
                    (r2.stdout or "").strip()[:200],
                )
                for stream in (r2.stdout, r2.stderr):
                    blob = try_parse_json(stream or "")
                    if blob:
                        raw_output = blob
                        detected_format = fmt
                        found = True
                        break
                if found:
                    break
                err2 = (r2.stderr or "").strip()
                if err2 or r2.returncode != 0:
                    attempt_errors.append(
                        f"{key_b} [exit={r2.returncode}]: {err2[:300] or '(no stderr)'}"
                    )

    if not raw_output:
        log.error(
            "Docker Scout returned no parseable JSON output. Attempted formats: %s. "
            "Strategies: %s",
            ", ".join(candidate_formats),
            "; ".join(attempts_desc[:4]),
        )
        if attempt_errors:
            log.error("Scout errors (first 4): %s", " | ".join(attempt_errors[:4]))
        sys.exit(1)

    log.info("Scout report format detected: %s", detected_format)

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
        """Extract a fixed/patched version string from Scout help/description text.

        Handles phrasings produced by different Scout versions, e.g.:
          "Upgrade to 1.1.1w"  |  "update to version 1.2.3"
          "Fixed in 1.1.1w"    |  "fixed in version 1.2.3"
          "resolved in 2.0"    |  "Upgrade openssl to 1.1.1w"
        """
        if not solution:
            return ""
        patterns = [
            # "upgrade/update [pkg] to [version]"
            r"\bupg(?:rade)?\s+(?:to\s+version\s+|to\s+)([^\s,;\)]+)",
            r"\bupdate\s+(?:to\s+version\s+|to\s+)([^\s,;\)]+)",
            # "to version X" / "to X" (general)
            r"\bto\s+version\s+([^\s,;\)]+)",
            r"\bto\s+([0-9][^\s,;\)]*)",
            # "fixed in version X" / "fixed in X"
            r"\bfixed\s+in\s+(?:version\s+)?([^\s,;\)]+)",
            # "resolved in X"
            r"\bresolved\s+in\s+(?:version\s+)?([^\s,;\)]+)",
            # "patched in X"
            r"\bpatched\s+in\s+(?:version\s+)?([^\s,;\)]+)",
        ]
        for pat in patterns:
            m = re.search(pat, solution, re.IGNORECASE)
            if m:
                candidate = m.group(1).strip().rstrip(".,;)")
                if candidate:
                    return candidate
        return ""

    if "packages" in data:
        # Scout legacy JSON format
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
        # Scout GitLab/generic JSON format
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
    elif "runs" in data:
        # SARIF 2.1.0 format (Docker Scout v1.22+).
        #
        # Docker Scout's SARIF layout has varied across minor versions.  This
        # parser tries every known field-name variant and data location so it
        # works regardless of which version produced the report:
        #
        #   Source A – result.properties  (per-location / per-package)
        #   Source B – rule.properties    (per-CVE metadata)
        #   Source C – locations[0].physicalLocation.artifactLocation.uri (PURL)
        #   Source D – locations[0].logicalLocations[0] (name + fullyQualifiedName)
        #   Source E – rule.help.text / rule.fullDescription.text (fixed version
        #              extracted via regex as absolute last resort)

        def _first(*values: str) -> str:
            """Return the first non-empty string from the candidates."""
            return next((v for v in values if v and str(v).strip()), "")

        runs = data.get("runs", [])
        log.debug("SARIF: %d run(s)", len(runs))

        for run in runs:
            driver = (run.get("tool", {}) or {}).get("driver", {}) or {}

            rules_by_id: dict[str, dict] = {}
            for rule in driver.get("rules", []):
                rid = rule.get("id", "")
                if rid:
                    rules_by_id[rid] = rule

            results = run.get("results", [])
            log.debug("SARIF: %d result(s) in this run", len(results))

            if results:
                # Dump the first result and its rule as raw JSON so any
                # future field-name mismatch is instantly visible in the log.
                log.debug(
                    "SARIF first result (raw): %s",
                    json.dumps(results[0])[:1500],
                )
                first_rule = rules_by_id.get(results[0].get("ruleId", ""), {})
                log.debug(
                    "SARIF first rule (raw): %s",
                    json.dumps(first_rule)[:1500],
                )

            # ── Helper: parse Scout's structured message.text table ─────────
            # Docker Scout v1.23+ embeds a key:value table in result.message.text:
            #   "Severity         :LOW\nPackage          :pkg:npm/foo@1.0\n..."
            # Returns a dict with lower-cased, stripped keys.
            def _parse_msg_table(text: str) -> dict[str, str]:
                out: dict[str, str] = {}
                for line in (text or "").splitlines():
                    if ":" in line:
                        key, _, val = line.partition(":")
                        key_clean = key.strip().lower().replace(" ", "_")
                        val_clean = val.strip()
                        if key_clean and val_clean:
                            out[key_clean] = val_clean
                return out

            # ── Helper: extract package data from a PURL string ───────────────
            def _apply_purl(
                purl: str,
                pkg: str,
                ver: str,
                typ: str,
            ) -> tuple[str, str, str]:
                if not purl.startswith("pkg:"):
                    return pkg, ver, typ
                pkg = pkg or package_from_purl(purl)
                if not ver and "@" in purl:
                    ver = purl.split("@", 1)[-1].split("?")[0]
                typ = typ or package_type_from_purl(purl)
                return pkg, ver, typ

            for result in results:
                rule_id    = result.get("ruleId", "")
                rule       = rules_by_id.get(rule_id, {})
                res_props  = result.get("properties", {}) or {}
                rule_props = rule.get("properties", {}) or {}

                # ── Source A: result.properties (older Scout / future versions) ─
                pkg_name      = _first(
                    res_props.get("affected_package", ""),
                    res_props.get("affected_package_name", ""),
                    res_props.get("package_name", ""),
                    res_props.get("package", ""),
                    res_props.get("name", ""),
                )
                installed_ver = _first(
                    res_props.get("affected_package_version", ""),
                    res_props.get("installed_version", ""),
                    res_props.get("version", ""),
                )
                fixed_ver     = _first(
                    res_props.get("fixed_version", ""),
                    res_props.get("fix_version", ""),
                    res_props.get("patched_version", ""),
                    res_props.get("remediation_version", ""),
                )
                pkg_type      = _first(
                    res_props.get("package_type", ""),
                    res_props.get("ecosystem", ""),
                    res_props.get("type", ""),
                ).lower()
                sev_raw       = _first(
                    res_props.get("cvss_severity", ""),
                    res_props.get("cvssV3_severity", ""),
                    res_props.get("severity", ""),
                )

                # ── Source B: rule.properties ─────────────────────────────────
                # Scout v1.23 puts ALL data here (result.properties is empty).
                #
                # Known fields (from live run debug output):
                #   purls            → list[str] of PURLs, e.g. ["pkg:npm/foo@1.0"]
                #   fixed_version    → "2.0.2"
                #   affected_version → version range (not exact; use PURL for exact)
                #   cvssV3_severity  → "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"
                #   security-severity→ numeric CVSS string
                pkg_name = pkg_name or _first(
                    rule_props.get("affected_package", ""),
                    rule_props.get("affected_package_name", ""),
                    rule_props.get("package_name", ""),
                    rule_props.get("package", ""),
                )
                fixed_ver     = fixed_ver or _first(
                    rule_props.get("fixed_version", ""),
                    rule_props.get("fix_version", ""),
                    rule_props.get("patched_version", ""),
                )
                sev_raw       = sev_raw or _first(
                    rule_props.get("cvssV3_severity", ""),
                    rule_props.get("cvss_severity", ""),
                    rule_props.get("severity", ""),
                )

                # rule_props.purls is the canonical package identity in v1.23
                purls_field = rule_props.get("purls", []) or []
                if isinstance(purls_field, str):
                    purls_field = [purls_field]
                for purl_str in purls_field:
                    if isinstance(purl_str, str):
                        pkg_name, installed_ver, pkg_type = _apply_purl(
                            purl_str, pkg_name, installed_ver, pkg_type
                        )
                        break  # first PURL is enough

                # ── Source C: result.message.text structured table ────────────
                # Scout v1.23 always includes a labeled table in message.text:
                #   "Package          :pkg:npm/brace-expansion@2.0.1"
                #   "Fixed version    :2.0.2"
                #   "Severity         :LOW"
                msg_table = _parse_msg_table(result.get("message", {}).get("text", ""))
                msg_pkg_purl = msg_table.get("package", "")
                pkg_name, installed_ver, pkg_type = _apply_purl(
                    msg_pkg_purl, pkg_name, installed_ver, pkg_type
                )
                fixed_ver = fixed_ver or msg_table.get("fixed_version", "")
                sev_raw   = sev_raw   or msg_table.get("severity", "")

                # ── Source D: locations (artifactLocation PURL, logicalLocations)
                for loc in result.get("locations", []):
                    phy = loc.get("physicalLocation", {}) or {}
                    purl = phy.get("artifactLocation", {}).get("uri", "")
                    pkg_name, installed_ver, pkg_type = _apply_purl(
                        purl, pkg_name, installed_ver, pkg_type
                    )
                    for ll in (loc.get("logicalLocations", []) or []):
                        if not pkg_name:
                            pkg_name = ll.get("name", "")
                        if not installed_ver:
                            fqn = ll.get("fullyQualifiedName", "")
                            if "@" in fqn:
                                installed_ver = fqn.split("@", 1)[-1]
                    snippet = phy.get("region", {}).get("snippet", {}).get("text", "")
                    if snippet and not pkg_name:
                        parts = snippet.split()
                        pkg_name      = pkg_name or (parts[0] if parts else "")
                        installed_ver = installed_ver or (parts[1] if len(parts) > 1 else "")

                # ── Source E: rule help / description text (fixed_version only) ─
                if not fixed_ver:
                    help_text = _first(
                        (rule.get("help", {}) or {}).get("text", ""),
                        (rule.get("help", {}) or {}).get("markdown", ""),
                        (rule.get("fullDescription", {}) or {}).get("text", ""),
                    )
                    if help_text:
                        fixed_ver = fixed_from_solution(help_text)

                # ── Map SARIF native level → severity ─────────────────────────
                _sarif_level = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}
                sev_final = sev_raw or result.get("level", "UNKNOWN")
                if sev_final.lower() in _sarif_level and sev_final.upper() not in SEVERITY_ORDER:
                    sev_final = _sarif_level[sev_final.lower()]

                desc = (rule.get("shortDescription", {}) or {}).get("text", "") or ""

                if not pkg_name:
                    log.debug(
                        "SARIF: skipping result with no package name (ruleId=%r "
                        "res_props_keys=%s rule_props_keys=%s)",
                        rule_id,
                        list(res_props.keys())[:8],
                        list(rule_props.keys())[:8],
                    )
                    continue

                cves.append(
                    CVE(
                        vuln_id=rule_id,
                        pkg_name=pkg_name,
                        installed_version=installed_ver,
                        fixed_version=fixed_ver,
                        severity=normalize_severity(sev_final),
                        package_type=pkg_type,
                        description=desc[:120],
                    )
                )

        fixable_count = sum(1 for c in cves if c.fixed_version)
        log.debug(
            "SARIF parse complete: %d CVE(s) extracted, %d with non-empty fixed_version",
            len(cves),
            fixable_count,
        )
    elif "components" in data or "metadata" in data:
        # CycloneDX JSON format
        for vuln in data.get("vulnerabilities", []):
            vid = vuln.get("id", "")
            sev_raw = "UNKNOWN"
            ratings = vuln.get("ratings", [])
            if ratings:
                sev_raw = ratings[0].get("severity", "UNKNOWN")

            fixed_ver = ""
            for affect in vuln.get("affects", []):
                for ver_entry in affect.get("versions", []):
                    if ver_entry.get("status") == "unaffected":
                        fixed_ver = ver_entry.get("version", "")
                        break
                if fixed_ver:
                    break

            for affect in vuln.get("affects", []):
                ref = affect.get("ref", "")
                comp = next(
                    (c for c in data.get("components", []) if c.get("bom-ref") == ref),
                    {},
                )
                pkg_name = comp.get("name", "")
                installed_ver = comp.get("version", "")
                pkg_type = (comp.get("type", "") or "").lower()

                if not pkg_name:
                    continue

                cves.append(
                    CVE(
                        vuln_id=vid,
                        pkg_name=pkg_name,
                        installed_version=installed_ver,
                        fixed_version=fixed_ver,
                        severity=normalize_severity(sev_raw),
                        package_type=pkg_type,
                        description=(vuln.get("description", "") or "")[:120],
                    )
                )
    else:
        top_keys = list(data.keys())[:6]
        log.warning(
            "Unrecognized Scout JSON schema — no CVEs extracted. "
            "Top-level keys: %s",
            top_keys,
        )

    if not cves and data:
        # Emit the top-level structure so users can file a bug report with context.
        top_keys = list(data.keys())[:6]
        runs_len  = len(data.get("runs", [])) if "runs" in data else None
        log.warning(
            "Scout report was parsed but yielded 0 CVEs. "
            "Schema keys=%s runs=%s. "
            "This may indicate a format mismatch — check the uploaded vuln_reports artifact "
            "and open an issue with the scout JSON sample.",
            top_keys,
            runs_len,
        )

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

    # Engine-compatibility flags:
    #   npm  -- --legacy-peer-deps skips strict engine/peer checks.
    #   yarn -- --ignore-engines prevents Yarn Classic (v1) from aborting
    #            when a dep's engines.node requires a newer Node version.
    #   pnpm -- --config.engine-strict=false achieves the same thing.
    app_install_steps = []
    for mgr in managers:
        if mgr == "npm":
            app_install_steps.append(
                f"if command -v npm >/dev/null 2>&1; then "
                f"npm install --no-audit --no-fund --legacy-peer-deps {joined}; exit 0; fi; "
            )
        elif mgr == "yarn":
            app_install_steps.append(
                f"if command -v yarn >/dev/null 2>&1; then "
                f"yarn add --ignore-engines {joined}; exit 0; fi; "
            )
        elif mgr == "pnpm":
            app_install_steps.append(
                f"if command -v pnpm >/dev/null 2>&1; then "
                f"pnpm add --config.engine-strict=false {joined}; exit 0; fi; "
            )
    manager_chain = "".join(app_install_steps)

    # Also patch npm's OWN bundled node_modules.
    # Node.js base images (e.g. node:18-alpine) bundle npm inside
    # /usr/local/lib/node_modules/npm/ and npm ships its own nested
    # node_modules with pinned versions (e.g. brace-expansion@2.0.1,
    # tar@6.x, minimatch@9.x).  Docker Scout scans ALL node_modules in the
    # image — including these bundled copies — so installing a patched version
    # elsewhere does NOT silence the CVE.  We must update npm's bundled deps
    # in-place by running `npm install` inside the npm package directory.
    patch_npm_bundled = (
        "NPM_BUNDLED=$(npm root -g 2>/dev/null || echo ''); "
        "if [ -n \"$NPM_BUNDLED\" ] && [ -d \"$NPM_BUNDLED/npm\" ]; then "
        f"cd \"$NPM_BUNDLED/npm\" && npm install --no-save --no-audit --no-fund --legacy-peer-deps {joined} 2>/dev/null || true; "
        "fi; "
    )

    return [
        "RUN set -eu; \\",
        # ── Step 1: patch app-level or global node_modules ──────────────────
        "    app_dir=$(find / -maxdepth 3 -name package.json -not -path '*/node_modules/*' -type f 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true); \\",
        "    if [ -n \"$app_dir\" ] && [ -f \"$app_dir/package.json\" ]; then \\",
        "      cd \"$app_dir\"; \\",
        f"      {manager_chain} \\",
        "      echo 'No Node package manager found in image.'; exit 1; \\",
        "    else \\",
        "      if command -v npm >/dev/null 2>&1; then npm install -g --no-audit --no-fund --legacy-peer-deps " + joined + "; exit 0; fi; \\",
        "      if command -v yarn >/dev/null 2>&1; then yarn global add --ignore-engines " + joined + "; exit 0; fi; \\",
        "      if command -v pnpm >/dev/null 2>&1; then pnpm add -g --config.engine-strict=false " + joined + "; exit 0; fi; \\",
        "      echo 'No Node package manager found in image.'; exit 1; \\",
        "    fi; \\",
        # ── Step 2: also update npm's own bundled node_modules ───────────────
        "    " + patch_npm_bundled + "true",
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
    # Always track the best (most-patched) image produced so far so we can
    # output it even when CVEs remain after max iterations.
    best_patched_tag: Optional[str] = None
    patched_tag = None
    final_scan = None
    remaining_fixable = current_fixable

    # Stagnation detection: if the exact set of (cve_id, pkg, version) tuples
    # doesn't change between two consecutive iterations we are stuck — the
    # remaining CVEs cannot be resolved by additional patching passes (e.g.
    # the fixed APK version is not yet in the repo, or the vulnerable copy
    # lives deep inside npm's own bundled node_modules and cannot be overridden
    # by a simple install).  Stop early rather than burning all 5 iterations.
    def _cve_fingerprint(cves: list[CVE]) -> frozenset[tuple[str, str, str]]:
        return frozenset(
            (c.vuln_id, c.pkg_name, c.installed_version) for c in cves
        )

    prev_fingerprint: Optional[frozenset] = None

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
        best_patched_tag = iteration_patched_tag  # track best achieved so far

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
            log.info("Iteration %d: All fixable CVEs resolved!", iteration)
            patched_tag = iteration_patched_tag
            final_scan = verification_scan
            break

        # ── Stagnation check ────────────────────────────────────────────────
        current_fp = _cve_fingerprint(remaining_fixable)
        if prev_fingerprint is not None and current_fp == prev_fingerprint:
            log.warning(
                "Iteration %d: CVE set unchanged from previous iteration — "
                "no further progress is possible with the current patching "
                "strategy (the remaining CVEs may require package versions not "
                "yet available in the distro repositories, or they reside in "
                "deeply-nested bundled node_modules that cannot be overridden "
                "by a simple install).  Stopping early with best-effort result.",
                iteration,
            )
            break
        prev_fingerprint = current_fp

        log.warning(
            "Iteration %d: %d fixable CVE(s) remain. Looping for next pass...",
            iteration,
            len(remaining_fixable),
        )
        current_image = iteration_patched_tag
        current_fixable = remaining_fixable

    # ── Post-loop: decide exit path ──────────────────────────────────────────
    # Use the best achieved image regardless of whether all CVEs were resolved.
    # A partial fix (fewer CVEs than baseline) is still valuable; the caller
    # can decide whether to enforce zero-CVE policy.
    output_tag = patched_tag or best_patched_tag or args.image

    if remaining_fixable:
        if verification_scan:
            print_report(
                verification_scan,
                remaining_fixable,
                severities,
                title="Final Verification Report (Partial Patch — some CVEs remain)",
            )
        log.warning(
            "Patching complete with partial results: %d fixable CVE(s) could not "
            "be resolved.  This is typically caused by (a) fixed APK package "
            "versions not yet available in the distro repos, or (b) vulnerable "
            "packages embedded deep inside npm's own bundled node_modules.  "
            "The best-effort patched image has been output.",
            len(remaining_fixable),
        )
        # Still write the best-effort image so downstream steps get a tag.
        if args.push and output_tag != args.image:
            push_image(output_tag)
        print_summary(
            original_image=args.image,
            patched_tag=output_tag,
            generated_dockerfile_path=generated_dockerfile_path,
            requested_fixes=len(baseline_fixable),
            attempted_fixes=total_patches_applied,
            remaining_fixes=len(remaining_fixable),
            pushed=args.push and output_tag != args.image,
        )
        _write_image_output(args.image_output_file, output_tag)
        return 0

    # FULL SUCCESS PATH
    if final_scan:
        print_report(
            final_scan,
            [],
            severities,
            title="Final Verification Report (ZERO VULNERABILITIES - SAFE TO PUSH)",
        )

    if args.push and patched_tag:
        push_image(patched_tag)

    print_summary(
        original_image=args.image,
        patched_tag=output_tag,
        generated_dockerfile_path=generated_dockerfile_path,
        requested_fixes=len(baseline_fixable),
        attempted_fixes=total_patches_applied,
        remaining_fixes=0,
        pushed=args.push and patched_tag is not None,
    )
    _write_image_output(args.image_output_file, output_tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
