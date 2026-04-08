import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)

_BUILD_SYSTEM_FILES = {
    "go.mod": ("go", "go_modules"),
    "pom.xml": ("java", "maven"),
    "build.gradle": ("java", "gradle"),
    "build.gradle.kts": ("java", "gradle_kotlin"),
}


def _run_git(args: list[str], cwd: str | None = None, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=timeout,
    )


def _get_commit_sha(repo_path: str) -> str | None:
    try:
        result = _run_git(["rev-parse", "HEAD"], cwd=repo_path, timeout=10)
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


@register_tool(sandbox_execution=False)
def setup_repo(
    repo: str,
    run_name: str,
    branch: str = "main",
) -> dict[str, Any]:
    """Clone a git URL or register a local path/folder as the audit target.

    Safe to call multiple times — skips clone if dest already exists.
    Returns the absolute local path and Docker workspace subdir.
    """
    if not repo or not repo.strip():
        return {"success": False, "error": "repo cannot be empty"}
    if not run_name or not run_name.strip():
        return {"success": False, "error": "run_name cannot be empty"}

    repo = repo.strip()
    run_name = run_name.strip()

    is_url = repo.startswith(("http://", "https://", "git@", "ssh://"))

    if is_url:
        dest = Path("strix_runs") / run_name / "repo"
        dest.parent.mkdir(parents=True, exist_ok=True)

        if dest.exists():
            commit_sha = _get_commit_sha(str(dest))
            return {
                "success": True,
                "repo_path": str(dest.resolve()),
                "branch": branch,
                "commit_sha": commit_sha,
                "is_clone": True,
                "workspace_subdir": "repo",
                "note": "Repository already cloned — skipped.",
            }

        clone_args = ["clone", "--depth", "50", "--branch", branch, repo, str(dest)]
        try:
            result = _run_git(clone_args, timeout=180)
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "git clone timed out after 180 seconds"}
        except FileNotFoundError:
            return {"success": False, "error": "git not found — install git and retry"}

        if result.returncode != 0:
            stderr = result.stderr.strip()
            # Branch may not exist — try without --branch
            if "Remote branch" in stderr or "not found" in stderr.lower():
                clone_args_no_branch = ["clone", "--depth", "50", repo, str(dest)]
                try:
                    result2 = _run_git(clone_args_no_branch, timeout=180)
                except subprocess.TimeoutExpired:
                    return {"success": False, "error": "git clone timed out"}
                if result2.returncode != 0:
                    return {"success": False, "error": f"git clone failed: {result2.stderr.strip()}"}
                actual_branch = "HEAD"
            else:
                return {"success": False, "error": f"git clone failed: {stderr}"}
        else:
            actual_branch = branch

        commit_sha = _get_commit_sha(str(dest))
        return {
            "success": True,
            "repo_path": str(dest.resolve()),
            "branch": actual_branch,
            "commit_sha": commit_sha,
            "is_clone": True,
            "workspace_subdir": "repo",
        }

    # Local path or folder
    local_path = Path(repo)
    if not local_path.exists():
        return {"success": False, "error": f"Path does not exist: {repo}"}
    if not local_path.is_dir():
        return {"success": False, "error": f"Path is not a directory: {repo}"}

    commit_sha = _get_commit_sha(str(local_path))
    return {
        "success": True,
        "repo_path": str(local_path.resolve()),
        "branch": branch,
        "commit_sha": commit_sha,
        "is_clone": False,
        "workspace_subdir": local_path.name,
    }


@register_tool(sandbox_execution=False)
def detect_language(
    repo_path: str,
    hint: str = "auto",
) -> dict[str, Any]:
    """Detect the primary programming language of a repository.

    Checks for go.mod, pom.xml, build.gradle, build.gradle.kts.
    Recurses one level for multi-module projects.
    """
    if not repo_path or not repo_path.strip():
        return {"success": False, "error": "repo_path cannot be empty"}

    if hint in ("go", "java"):
        return {
            "success": True,
            "detected": hint,
            "build_system": "go_modules" if hint == "go" else "maven",
            "evidence": [f"hint={hint}"],
        }

    root = Path(repo_path.strip())
    if not root.exists():
        return {"success": False, "error": f"Path does not exist: {repo_path}"}

    # Check root level
    for filename, (lang, build_system) in _BUILD_SYSTEM_FILES.items():
        if (root / filename).exists():
            return {
                "success": True,
                "detected": lang,
                "build_system": build_system,
                "evidence": [filename],
            }

    # One level deeper (multi-module repos)
    for subdir in root.iterdir():
        if not subdir.is_dir() or subdir.name.startswith("."):
            continue
        for filename, (lang, build_system) in _BUILD_SYSTEM_FILES.items():
            if (subdir / filename).exists():
                return {
                    "success": True,
                    "detected": lang,
                    "build_system": build_system,
                    "evidence": [f"{subdir.name}/{filename}"],
                }

    return {
        "success": True,
        "detected": "unknown",
        "build_system": "unknown",
        "evidence": [],
        "note": "Could not detect language — specify --lang go or --lang java",
    }


@register_tool(sandbox_execution=False)
def write_fix_proposal(
    run_name: str,
    finding_id: str,
    file_path: str,
    unified_diff: str,
    test_code: str = "",
    test_file_path: str = "",
) -> dict[str, Any]:
    """Write a fix proposal (unified diff + optional test code) for human review.

    Never applies the fix — only writes files for human inspection.
    Proposals are written to strix_runs/<run_name>/proposals/<finding_id>/.
    """
    if not run_name or not run_name.strip():
        return {"success": False, "error": "run_name cannot be empty"}
    if not finding_id or not finding_id.strip():
        return {"success": False, "error": "finding_id cannot be empty"}
    if not unified_diff or not unified_diff.strip():
        return {"success": False, "error": "unified_diff cannot be empty"}

    proposal_dir = Path("strix_runs") / run_name.strip() / "proposals" / finding_id.strip()
    proposal_dir.mkdir(parents=True, exist_ok=True)

    diff_file = proposal_dir / "fix.diff"
    diff_file.write_text(unified_diff, encoding="utf-8")

    written: list[str] = [str(diff_file)]

    if test_code and test_code.strip():
        test_fname = test_file_path.strip() if test_file_path and test_file_path.strip() else "fix_test.go"
        # Sanitize: strip leading slashes/workspace prefixes
        test_fname = test_fname.lstrip("/").replace("\\", "/")
        if "/" in test_fname:
            test_fname = Path(test_fname).name
        test_file = proposal_dir / test_fname
        test_file.write_text(test_code, encoding="utf-8")
        written.append(str(test_file))

    return {
        "success": True,
        "proposal_dir": str(proposal_dir.resolve()),
        "diff_file": str(diff_file.resolve()),
        "files_written": written,
        "note": "Fix proposal written for human review — NOT applied automatically.",
    }

