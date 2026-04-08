"""Narrow-purpose scanning tools for code audit sub-agents.

Each tool:
  1. Checks if the scanner is installed (skips gracefully if not)
  2. Runs the scanner as a subprocess
  3. Parses its output internally
  4. Calls create_code_finding() for each result
  5. Returns a clean summary — the LLM never sees raw scanner JSON/XML

agent_state is auto-injected by the tool runner — do NOT include in schema.
"""
import json
import logging
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool
from strix.tools.code.reporting_actions import create_code_finding


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(command: str, cwd: str, timeout: int = 300) -> tuple[int, str, str]:
    """Run a shell command; return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            cwd=cwd or None,
            timeout=timeout,
        )
        return r.returncode, r.stdout[:200_000], r.stderr[:20_000]
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"
    except Exception as exc:
        return -1, "", str(exc)


def _rel(file_path: str, repo_path: str) -> str:
    """Return file_path relative to repo_path, or as-is if not under it."""
    try:
        return str(Path(file_path).relative_to(repo_path))
    except (ValueError, TypeError):
        return file_path


def _parse_modules(modules_json: str, repo_path: str) -> list[Path]:
    """Parse a JSON array of module paths (relative or absolute) into Path objects."""
    try:
        raw = json.loads(modules_json)
        if not isinstance(raw, list):
            raw = [modules_json]
    except (json.JSONDecodeError, ValueError):
        raw = [m.strip() for m in modules_json.split(",") if m.strip()]

    result: list[Path] = []
    for m in raw:
        p = Path(m) if Path(m).is_absolute() else Path(repo_path) / m
        if p.exists():
            result.append(p)
        else:
            logger.warning("Module path not found, skipping: %s", p)
    return result


# ---------------------------------------------------------------------------
# Gosec — Go security scanner
# ---------------------------------------------------------------------------

_GOSEC_IMPACTS: dict[str, str] = {
    "G101": "Hardcoded credentials allow unauthorized access to protected resources",
    "G102": "Binding to all interfaces exposes the service to unintended network access",
    "G103": "unsafe package bypasses Go memory safety; can cause memory corruption",
    "G104": "Unhandled errors mask failures and leave the system in an undefined state",
    "G106": "InsecureIgnoreHostKey disables SSH host verification, enabling MITM attacks",
    "G107": "Dynamic URL construction with user input can lead to SSRF",
    "G108": "Exposed profiling endpoint leaks internal metrics and memory data",
    "G110": "Decompression bomb can exhaust available memory",
    "G111": "Directory traversal can expose files outside the intended root",
    "G201": "String-concatenated SQL query is vulnerable to SQL injection",
    "G202": "String-concatenated SQL query is vulnerable to SQL injection",
    "G203": "Template injection can result in stored or reflected XSS",
    "G204": "OS command injection allows arbitrary command execution on the host",
    "G304": "File path from variable can lead to path traversal",
    "G305": "Archive extraction path traversal (zip slip) can overwrite arbitrary files",
    "G401": "MD5 is cryptographically broken; collision attacks are practical",
    "G402": "Weak TLS configuration allows downgrade attacks",
    "G403": "RSA key below 2048 bits is considered insecure",
    "G404": "Weak PRNG output is predictable; unsuitable for security-sensitive use",
    "G501": "MD5 is cryptographically broken",
    "G502": "DES is cryptographically broken",
    "G505": "SHA1 is cryptographically broken for collision resistance",
}


@register_tool(sandbox_execution=False)
def run_gosec(
    agent_state: Any,
    repo_path: str,
    modules_json: str,
) -> dict[str, Any]:
    """Run gosec security scanner on Go module directories.

    Runs `gosec -fmt json ./...` in each module directory listed in modules_json.
    modules_json must be a JSON array of paths relative to repo_path, e.g.
    '["api/", "workers/platform/", "workers/graph/"]'.

    Auto-records findings via create_code_finding — returns a summary only.
    """
    if not shutil.which("gosec"):
        return {
            "success": False,
            "skipped": True,
            "reason": "gosec not installed — install: go install github.com/securego/gosec/v2/cmd/gosec@latest",
        }
    if not repo_path or not repo_path.strip():
        return {"success": False, "error": "repo_path cannot be empty"}
    if not modules_json or not modules_json.strip():
        return {"success": False, "error": "modules_json cannot be empty"}

    repo_path = repo_path.strip()
    modules = _parse_modules(modules_json.strip(), repo_path)
    if not modules:
        return {"success": False, "error": "No valid module paths found in modules_json"}

    findings_recorded = 0
    modules_scanned: list[str] = []
    modules_failed: list[str] = []
    severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

    for mod_path in modules:
        rc, stdout, stderr = _run("gosec -fmt json -quiet ./...", str(mod_path), timeout=300)

        if not stdout.strip():
            modules_failed.append(f"{mod_path.name}: no output — {stderr[:200]}")
            continue

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            modules_failed.append(f"{mod_path.name}: JSON parse error")
            continue

        issues = data.get("Issues") or []
        for issue in issues:
            severity = severity_map.get((issue.get("severity") or "MEDIUM").upper(), "medium")
            rule_id = issue.get("rule_id") or "gosec-unknown"
            file_path = _rel(issue.get("file") or "", repo_path)

            try:
                line_no = int(issue.get("line") or 0)
            except (ValueError, TypeError):
                line_no = 0

            details = issue.get("details") or "Security issue detected by gosec"
            cwe_val = ""
            if isinstance(issue.get("cwe"), dict):
                cwe_val = issue["cwe"].get("id") or ""

            res = create_code_finding(
                agent_state=agent_state,
                finding_type="sast",
                severity=severity,
                rule_id=rule_id,
                file_path=file_path,
                line_number=line_no,
                description=f"{rule_id}: {details}",
                impact=_GOSEC_IMPACTS.get(rule_id, f"Security vulnerability that may lead to system compromise — {details[:120]}"),
                source_tool="gosec",
                cwe=cwe_val,
                remediation=issue.get("details") or "",
            )
            if res.get("success"):
                findings_recorded += 1

        modules_scanned.append(str(mod_path.relative_to(Path(repo_path))))

    return {
        "success": True,
        "findings_recorded": findings_recorded,
        "modules_scanned": modules_scanned,
        "modules_failed": modules_failed,
    }


# ---------------------------------------------------------------------------
# Semgrep — SAST for Go and Java
# ---------------------------------------------------------------------------

@register_tool(sandbox_execution=False)
def run_semgrep(
    agent_state: Any,
    repo_path: str,
    language: str,
    scan_paths_json: str = ".",
) -> dict[str, Any]:
    """Run semgrep SAST scanner on the repository.

    language must be "go" or "java" — selects the appropriate ruleset.
    scan_paths_json is a JSON array of paths relative to repo_path to scan,
    e.g. '["api/", "workers/"]'. Defaults to "." (entire repo).

    Auto-records findings via create_code_finding — returns a summary only.
    """
    if not shutil.which("semgrep"):
        return {
            "success": False,
            "skipped": True,
            "reason": "semgrep not installed — install: pip install semgrep",
        }
    if not repo_path or not repo_path.strip():
        return {"success": False, "error": "repo_path cannot be empty"}

    language = (language or "").strip().lower()
    if language not in ("go", "java"):
        return {"success": False, "error": "language must be 'go' or 'java'"}

    ruleset = "p/golang" if language == "go" else "p/java"

    # Build list of paths to scan
    try:
        raw_paths = json.loads(scan_paths_json.strip() if scan_paths_json else ".")
        if not isinstance(raw_paths, list):
            raw_paths = ["."]
    except (json.JSONDecodeError, ValueError):
        raw_paths = ["."]

    scan_targets = " ".join(
        str(Path(repo_path) / p) if not Path(p).is_absolute() else p
        for p in raw_paths
    )

    cmd = f"semgrep scan --config {ruleset} --json --timeout 120 {scan_targets}"
    rc, stdout, stderr = _run(cmd, repo_path, timeout=360)

    if not stdout.strip():
        return {
            "success": False,
            "skipped": False,
            "error": f"semgrep produced no output — {stderr[:300]}",
        }

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {"success": False, "error": "Failed to parse semgrep JSON output"}

    results = data.get("results") or []
    findings_recorded = 0
    rules_matched: set[str] = set()
    sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

    for r in results:
        check_id = r.get("check_id") or "semgrep-unknown"
        file_path = _rel(r.get("path") or "", repo_path)
        line_no = (r.get("start") or {}).get("line") or 0
        extra = r.get("extra") or {}
        message = extra.get("message") or "Security issue detected by semgrep"
        raw_sev = (extra.get("severity") or "WARNING").upper()
        severity = sev_map.get(raw_sev, "medium")

        meta = extra.get("metadata") or {}
        cwe_list = meta.get("cwe") or []
        cwe_val = cwe_list[0] if cwe_list else ""

        res = create_code_finding(
            agent_state=agent_state,
            finding_type="sast",
            severity=severity,
            rule_id=check_id,
            file_path=file_path,
            line_number=int(line_no),
            description=f"{check_id}: {message}",
            impact=f"Exploitation of {check_id} could compromise application security — {message[:120]}",
            source_tool="semgrep",
            cwe=str(cwe_val) if cwe_val else "",
            remediation=meta.get("fix") or "",
        )
        if res.get("success"):
            findings_recorded += 1
            rules_matched.add(check_id)

    return {
        "success": True,
        "findings_recorded": findings_recorded,
        "rules_matched": sorted(rules_matched),
        "total_semgrep_results": len(results),
    }


# ---------------------------------------------------------------------------
# golangci-lint — Go code quality
# ---------------------------------------------------------------------------

_GOLANGCI_SEVERITIES: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "": "low",
}


@register_tool(sandbox_execution=False)
def run_golangci_lint(
    agent_state: Any,
    repo_path: str,
    modules_json: str,
) -> dict[str, Any]:
    """Run golangci-lint code quality scanner on Go module directories.

    modules_json must be a JSON array of paths relative to repo_path, e.g.
    '["api/", "workers/platform/"]'.

    Auto-records findings via create_code_finding — returns a summary only.
    """
    if not shutil.which("golangci-lint"):
        return {
            "success": False,
            "skipped": True,
            "reason": "golangci-lint not installed — see https://golangci-lint.run/usage/install/",
        }
    if not repo_path or not repo_path.strip():
        return {"success": False, "error": "repo_path cannot be empty"}
    if not modules_json or not modules_json.strip():
        return {"success": False, "error": "modules_json cannot be empty"}

    repo_path = repo_path.strip()
    modules = _parse_modules(modules_json.strip(), repo_path)
    if not modules:
        return {"success": False, "error": "No valid module paths found in modules_json"}

    findings_recorded = 0
    modules_scanned: list[str] = []
    modules_failed: list[str] = []
    linters_seen: set[str] = set()

    for mod_path in modules:
        rc, stdout, stderr = _run(
            "golangci-lint run --output.json.path stdout --timeout 120s ./...",
            str(mod_path),
            timeout=180,
        )
        if not stdout.strip() and "unknown flag" in stderr:
            rc, stdout, stderr = _run(
                "golangci-lint run --out-format json --timeout 120s ./...",
                str(mod_path),
                timeout=180,
            )

        if not stdout.strip():
            modules_failed.append(f"{mod_path.name}: no output — {stderr[:200]}")
            continue

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            modules_failed.append(f"{mod_path.name}: JSON parse error")
            continue

        issues = data.get("Issues") or []
        for issue in issues:
            linter = issue.get("FromLinter") or "golangci-lint"
            linters_seen.add(linter)
            text = issue.get("Text") or "Code quality issue"
            pos = issue.get("Pos") or {}
            file_path = _rel(pos.get("Filename") or "", repo_path)
            line_no = pos.get("Line") or 0
            raw_sev = (issue.get("Severity") or "").lower()
            severity = _GOLANGCI_SEVERITIES.get(raw_sev, "low")

            res = create_code_finding(
                agent_state=agent_state,
                finding_type="quality",
                severity=severity,
                rule_id=f"{linter}",
                file_path=file_path,
                line_number=int(line_no),
                description=f"{linter}: {text}",
                impact=f"Code quality issue reported by {linter} — may indicate latent bugs or maintainability risk",
                source_tool="golangci-lint",
                remediation=issue.get("Replacement", {}).get("NewLines", [""])[0] if isinstance(issue.get("Replacement"), dict) else "",
            )
            if res.get("success"):
                findings_recorded += 1

        modules_scanned.append(str(mod_path.relative_to(Path(repo_path))))

    return {
        "success": True,
        "findings_recorded": findings_recorded,
        "modules_scanned": modules_scanned,
        "modules_failed": modules_failed,
        "linters_triggered": sorted(linters_seen),
    }


# ---------------------------------------------------------------------------
# Checkstyle — Java code style
# ---------------------------------------------------------------------------

@register_tool(sandbox_execution=False)
def run_checkstyle(
    agent_state: Any,
    repo_path: str,
    checkstyle_jar: str = "",
    config: str = "google",
) -> dict[str, Any]:
    """Run Checkstyle on Java source files.

    checkstyle_jar: absolute path to the checkstyle JAR. If empty, looks for
    checkstyle on PATH (as `checkstyle`) or tries to download via Maven wrapper.
    config: "google" (default) or "sun" — selects the bundled check config.

    Auto-records findings via create_code_finding — returns a summary only.
    """
    if not repo_path or not repo_path.strip():
        return {"success": False, "error": "repo_path cannot be empty"}

    repo_path = repo_path.strip()

    # Determine how to invoke checkstyle
    if checkstyle_jar and Path(checkstyle_jar).exists():
        invoke = f"java -jar {checkstyle_jar}"
    elif shutil.which("checkstyle"):
        invoke = "checkstyle"
    else:
        return {
            "success": False,
            "skipped": True,
            "reason": "checkstyle not found — provide checkstyle_jar path or install checkstyle on PATH",
        }

    cfg_flag = "/google_checks.xml" if config == "google" else "/sun_checks.xml"
    cmd = f'{invoke} -c {cfg_flag} -f xml -r {repo_path}/src'
    rc, stdout, stderr = _run(cmd, repo_path, timeout=120)

    if not stdout.strip():
        return {"success": False, "error": f"checkstyle produced no output — {stderr[:300]}"}

    findings_recorded = 0
    files_checked: list[str] = []
    sev_map = {"error": "high", "warning": "medium", "info": "low", "ignore": "info"}

    try:
        root_el = ET.fromstring(stdout)
        for file_el in root_el.findall("file"):
            fname = _rel(file_el.get("name") or "", repo_path)
            if file_el.findall("error"):
                files_checked.append(fname)
            for err_el in file_el.findall("error"):
                line_no = int(err_el.get("line") or 0)
                severity = sev_map.get((err_el.get("severity") or "warning").lower(), "low")
                message = err_el.get("message") or "Checkstyle violation"
                source = err_el.get("source") or "checkstyle"
                rule_short = source.split(".")[-1] if "." in source else source

                res = create_code_finding(
                    agent_state=agent_state,
                    finding_type="quality",
                    severity=severity,
                    rule_id=f"checkstyle.{rule_short}",
                    file_path=fname,
                    line_number=line_no,
                    description=f"Checkstyle ({rule_short}): {message}",
                    impact="Code style violation that may reduce readability and increase maintenance cost",
                    source_tool="checkstyle",
                )
                if res.get("success"):
                    findings_recorded += 1
    except ET.ParseError as exc:
        return {"success": False, "error": f"Failed to parse checkstyle XML: {exc!s}"}

    return {
        "success": True,
        "findings_recorded": findings_recorded,
        "files_checked": len(files_checked),
    }


# ---------------------------------------------------------------------------
# PMD — Java static analysis
# ---------------------------------------------------------------------------

@register_tool(sandbox_execution=False)
def run_pmd(
    agent_state: Any,
    repo_path: str,
    pmd_bin: str = "",
) -> dict[str, Any]:
    """Run PMD static analysis on Java source files.

    pmd_bin: path to the PMD binary. If empty, looks for 'pmd' on PATH.
    Uses the Java quickstart ruleset.

    Auto-records findings via create_code_finding — returns a summary only.
    """
    if not repo_path or not repo_path.strip():
        return {"success": False, "error": "repo_path cannot be empty"}

    repo_path = repo_path.strip()

    if pmd_bin and Path(pmd_bin).exists():
        invoke = pmd_bin
    elif shutil.which("pmd"):
        invoke = "pmd"
    else:
        return {
            "success": False,
            "skipped": True,
            "reason": "pmd not found — install PMD and add to PATH",
        }

    src_dir = str(Path(repo_path) / "src")
    cmd = f"{invoke} check -d {src_dir} -R rulesets/java/quickstart.xml -f json --no-cache"
    rc, stdout, stderr = _run(cmd, repo_path, timeout=180)

    if not stdout.strip():
        return {"success": False, "error": f"PMD produced no output — {stderr[:300]}"}

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {"success": False, "error": "Failed to parse PMD JSON output"}

    # PMD priority: 1=high, 2=medium-high, 3=medium, 4=low, 5=info
    priority_map = {1: "high", 2: "high", 3: "medium", 4: "low", 5: "info"}
    findings_recorded = 0
    rules_triggered: set[str] = set()

    for file_entry in data.get("files") or []:
        fname = _rel(file_entry.get("filename") or "", repo_path)
        for v in file_entry.get("violations") or []:
            rule = v.get("rule") or "pmd-unknown"
            rules_triggered.add(rule)
            line_no = v.get("beginline") or 0
            priority = v.get("priority") or 3
            severity = priority_map.get(int(priority), "medium")
            description = v.get("description") or "PMD violation"

            res = create_code_finding(
                agent_state=agent_state,
                finding_type="quality",
                severity=severity,
                rule_id=f"pmd.{rule}",
                file_path=fname,
                line_number=int(line_no),
                description=f"PMD ({rule}): {description}",
                impact=f"Static analysis violation that may indicate bugs or code quality issues — {description[:100]}",
                source_tool="pmd",
                remediation=v.get("externalInfoUrl") or "",
            )
            if res.get("success"):
                findings_recorded += 1

    return {
        "success": True,
        "findings_recorded": findings_recorded,
        "rules_triggered": sorted(rules_triggered),
    }


# ---------------------------------------------------------------------------
# Go coverage
# ---------------------------------------------------------------------------

@register_tool(sandbox_execution=False)
def run_go_coverage(
    agent_state: Any,
    repo_path: str,
    modules_json: str,
    low_coverage_threshold: int = 50,
) -> dict[str, Any]:
    """Run go test with coverage profiling on Go module directories.

    modules_json must be a JSON array of paths relative to repo_path, e.g.
    '["api/", "workers/platform/"]'.

    low_coverage_threshold: packages below this % get a finding (default 50).
    Packages at exactly 0% coverage get a HIGH finding.
    Others below threshold get LOW findings.

    Auto-records findings via create_code_finding — returns a summary only.
    """
    if not shutil.which("go"):
        return {"success": False, "skipped": True, "reason": "go not found on PATH"}
    if not repo_path or not repo_path.strip():
        return {"success": False, "error": "repo_path cannot be empty"}
    if not modules_json or not modules_json.strip():
        return {"success": False, "error": "modules_json cannot be empty"}

    repo_path = repo_path.strip()
    modules = _parse_modules(modules_json.strip(), repo_path)
    if not modules:
        return {"success": False, "error": "No valid module paths found in modules_json"}

    findings_recorded = 0
    modules_scanned: list[str] = []
    modules_failed: list[str] = []
    module_totals: list[dict[str, Any]] = []

    for mod_path in modules:
        with tempfile.NamedTemporaryFile(suffix=".out", delete=False) as tf:
            cov_file = tf.name

        rc, stdout, stderr = _run(
            f"go test -coverprofile={cov_file} -covermode=atomic -timeout 300s ./...",
            str(mod_path),
            timeout=360,
        )

        if not Path(cov_file).exists() or Path(cov_file).stat().st_size < 5:
            modules_failed.append(f"{mod_path.name}: no coverage profile generated — {stderr[:200]}")
            continue

        # Get per-function coverage
        _, func_out, _ = _run(f"go tool cover -func={cov_file}", str(mod_path), timeout=30)

        module_rel = str(mod_path.relative_to(Path(repo_path)))
        total_pct: float = 0.0
        low_pkgs: list[str] = []

        for line in func_out.splitlines():
            line = line.strip()
            if line.startswith("total:"):
                try:
                    total_pct = float(line.split()[-1].rstrip("%"))
                except (ValueError, IndexError):
                    pass
            elif line.endswith("0.0%"):
                # Zero coverage function
                parts = line.split()
                if parts:
                    func_name = parts[1] if len(parts) >= 2 else parts[0]
                    file_part = parts[0].split(":")[0] if ":" in parts[0] else parts[0]
                    pkg_path = _rel(file_part, repo_path)
                    low_pkgs.append(f"{pkg_path}::{func_name} (0%)")

        module_totals.append({"module": module_rel, "total_pct": total_pct})
        modules_scanned.append(module_rel)

        # Record a coverage finding for this module
        severity = "info" if total_pct >= low_coverage_threshold else ("high" if total_pct == 0 else "low")
        res = create_code_finding(
            agent_state=agent_state,
            finding_type="coverage",
            severity=severity,
            rule_id="go-coverage-threshold",
            file_path=module_rel,
            line_number=0,
            description=f"Module {module_rel}: {total_pct:.1f}% test coverage",
            impact=f"Low test coverage ({total_pct:.1f}%) means bugs may go undetected. Functions with 0% coverage: {len(low_pkgs)}",
            source_tool="go-coverage",
            remediation=f"Add unit tests for uncovered functions. Zero-coverage items: {', '.join(low_pkgs[:5])}",
        )
        if res.get("success"):
            findings_recorded += 1

        # Clean up temp file
        try:
            Path(cov_file).unlink(missing_ok=True)
        except OSError:
            pass

    overall_avg = (
        sum(m["total_pct"] for m in module_totals) / len(module_totals)
        if module_totals else 0.0
    )

    return {
        "success": True,
        "findings_recorded": findings_recorded,
        "modules_scanned": modules_scanned,
        "modules_failed": modules_failed,
        "overall_avg_coverage_pct": round(overall_avg, 1),
        "module_totals": module_totals,
    }


# ---------------------------------------------------------------------------
# JaCoCo — Java test coverage
# ---------------------------------------------------------------------------

@register_tool(sandbox_execution=False)
def run_jacoco(
    agent_state: Any,
    repo_path: str,
    build_system: str = "auto",
    low_coverage_threshold: int = 50,
) -> dict[str, Any]:
    """Run JaCoCo test coverage for Java projects.

    build_system: "maven", "gradle", or "auto" (detected from repo).
    Runs tests and generates JaCoCo XML report, then parses it.

    Auto-records findings via create_code_finding — returns a summary only.
    """
    if not repo_path or not repo_path.strip():
        return {"success": False, "error": "repo_path cannot be empty"}

    repo_path = repo_path.strip()
    root = Path(repo_path)

    # Detect build system if auto
    if build_system == "auto":
        if (root / "pom.xml").exists():
            build_system = "maven"
        elif (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
            build_system = "gradle"
        else:
            return {"success": False, "error": "Cannot detect build system — no pom.xml or build.gradle found"}

    # Run tests with coverage
    if build_system == "maven":
        if not shutil.which("mvn"):
            return {"success": False, "skipped": True, "reason": "mvn not found on PATH"}
        rc, _, stderr = _run(
            "mvn test jacoco:report -q --no-transfer-progress",
            repo_path,
            timeout=600,
        )
        jacoco_xml = root / "target" / "site" / "jacoco" / "jacoco.xml"
    else:
        wrapper = "./gradlew" if (root / "gradlew").exists() else "gradle"
        if not shutil.which(wrapper.lstrip("./")):
            return {"success": False, "skipped": True, "reason": f"{wrapper} not found"}
        rc, _, stderr = _run(
            f"{wrapper} test jacocoTestReport --no-daemon -q",
            repo_path,
            timeout=600,
        )
        jacoco_xml = root / "build" / "reports" / "jacoco" / "test" / "jacocoTestReport.xml"

    if not jacoco_xml.exists():
        return {
            "success": False,
            "error": f"JaCoCo XML report not found at {jacoco_xml} — tests may have failed. stderr: {stderr[:400]}",
        }

    try:
        tree = ET.parse(str(jacoco_xml))
        root_el = tree.getroot()
    except ET.ParseError as exc:
        return {"success": False, "error": f"Failed to parse JaCoCo XML: {exc!s}"}

    findings_recorded = 0
    low_coverage_classes: list[str] = []
    total_missed = 0
    total_covered = 0

    for pkg_el in root_el.findall("package"):
        for cls_el in pkg_el.findall("class"):
            class_name = cls_el.get("name", "").replace("/", ".")
            source_file = cls_el.get("sourcefilename") or ""
            pkg_name = pkg_el.get("name", "").replace("/", ".")
            source_path = f"{pkg_el.get('name', '')}/{source_file}" if source_file else class_name

            # Get LINE counter
            line_counter = next(
                (c for c in cls_el.findall("counter") if c.get("type") == "LINE"),
                None,
            )
            if line_counter is None:
                continue

            missed = int(line_counter.get("missed") or 0)
            covered = int(line_counter.get("covered") or 0)
            total_missed += missed
            total_covered += covered
            total = missed + covered
            if total == 0:
                continue

            pct = (covered / total) * 100

            if pct < low_coverage_threshold:
                low_coverage_classes.append(f"{class_name} ({pct:.0f}%)")
                severity = "high" if pct == 0 else "low"
                res = create_code_finding(
                    agent_state=agent_state,
                    finding_type="coverage",
                    severity=severity,
                    rule_id="jacoco-coverage-threshold",
                    file_path=source_path,
                    line_number=0,
                    description=f"Low test coverage on {class_name}: {pct:.0f}% ({covered}/{total} lines)",
                    impact=f"Insufficient test coverage ({pct:.0f}%) means regressions and bugs may go undetected in production",
                    source_tool="jacoco",
                    remediation=f"Add JUnit tests covering the {missed} uncovered lines in {class_name}",
                )
                if res.get("success"):
                    findings_recorded += 1

    grand_total = total_missed + total_covered
    overall_pct = (total_covered / grand_total * 100) if grand_total > 0 else 0.0

    return {
        "success": True,
        "findings_recorded": findings_recorded,
        "overall_line_coverage_pct": round(overall_pct, 1),
        "low_coverage_classes": low_coverage_classes[:20],
        "total_classes_below_threshold": len(low_coverage_classes),
    }


# ---------------------------------------------------------------------------
# Gitleaks — secret detection
# ---------------------------------------------------------------------------

@register_tool(sandbox_execution=False)
def run_gitleaks(
    agent_state: Any,
    repo_path: str,
    scan_git_history: bool = True,
) -> dict[str, Any]:
    """Run gitleaks to detect hardcoded secrets and credentials.

    scan_git_history: if True (default), scans full git history in addition to
    the working tree. Set to False for non-git directories.

    Secrets are REDACTED in recorded findings — raw secret values are never stored.
    Auto-records findings via create_code_finding — returns a summary only.
    """
    if not shutil.which("gitleaks"):
        return {
            "success": False,
            "skipped": True,
            "reason": "gitleaks not installed — see https://github.com/gitleaks/gitleaks#installing",
        }
    if not repo_path or not repo_path.strip():
        return {"success": False, "error": "repo_path cannot be empty"}

    repo_path = repo_path.strip()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        report_file = tf.name

    try:
        if scan_git_history:
            cmd = f"gitleaks detect --source {repo_path} --report-format json --report-path {report_file} --exit-code 0"
        else:
            cmd = f"gitleaks detect --source {repo_path} --report-format json --report-path {report_file} --no-git --exit-code 0"

        rc, stdout, stderr = _run(cmd, repo_path, timeout=300)

        if not Path(report_file).exists():
            return {"success": False, "error": f"gitleaks report file not created — {stderr[:300]}"}

        try:
            raw = Path(report_file).read_text(encoding="utf-8")
            data = json.loads(raw) if raw.strip() else []
        except (json.JSONDecodeError, OSError):
            return {"success": False, "error": "Failed to read/parse gitleaks report"}

        findings_recorded = 0
        for leak in (data or []):
            rule_id = leak.get("RuleID") or "gitleaks-secret"
            description_short = leak.get("Description") or "Secret detected"
            file_path = _rel(leak.get("File") or "", repo_path)
            line_no = leak.get("StartLine") or 0
            commit = leak.get("Commit") or "working tree"
            # NEVER store the actual secret — redact it
            match_preview = (leak.get("Match") or "")[:60]

            res = create_code_finding(
                agent_state=agent_state,
                finding_type="secret",
                severity="critical",
                rule_id=rule_id,
                file_path=file_path,
                line_number=int(line_no),
                description=f"{description_short} detected by gitleaks (rule: {rule_id}) in commit {commit[:8]}",
                impact="Hardcoded credentials can be extracted from git history and used to gain unauthorized access to the affected service or resource",
                source_tool="gitleaks",
                remediation="Rotate the secret immediately, then remove it from git history using git-filter-repo or BFG Repo Cleaner",
            )
            if res.get("success"):
                findings_recorded += 1

        return {
            "success": True,
            "findings_recorded": findings_recorded,
            "git_history_scanned": scan_git_history,
        }
    finally:
        try:
            Path(report_file).unlink(missing_ok=True)
        except OSError:
            pass
