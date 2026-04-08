import logging
import os
import re
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)

_MAX_FILE_BYTES = 500_000  # 500 KB read limit per file
_MAX_SEARCH_RESULTS = 500


@register_tool(sandbox_execution=False)
def list_files_local(
    path: str,
    pattern: str = "**/*",
) -> dict[str, Any]:
    """List files in a directory, optionally filtered by glob pattern.

    Used in the fix proposal phase to locate source files before reading them.
    Returns file paths relative to the given path, with sizes in bytes.
    Directories are excluded — only files are returned.
    """
    if not path or not path.strip():
        return {"success": False, "error": "path cannot be empty"}

    root = Path(path.strip())
    if not root.exists():
        return {"success": False, "error": f"Path does not exist: {path}"}
    if not root.is_dir():
        return {"success": False, "error": f"Path is not a directory: {path}"}

    try:
        matched = sorted(root.glob(pattern.strip() if pattern and pattern.strip() else "**/*"))
        files = []
        for p in matched:
            if p.is_file():
                try:
                    size = p.stat().st_size
                except OSError:
                    size = -1
                files.append({"path": str(p.relative_to(root)), "size_bytes": size})

        return {
            "success": True,
            "root": str(root),
            "pattern": pattern,
            "count": len(files),
            "files": files[:1000],  # cap at 1000 entries
            "truncated": len(files) > 1000,
        }
    except Exception as e:
        return {"success": False, "error": f"Failed to list files: {e!s}"}


@register_tool(sandbox_execution=False)
def read_source_file(
    file_path: str,
    start_line: int = 1,
    end_line: int = 0,
) -> dict[str, Any]:
    """Read a source file with line numbers prepended.

    Used in the fix proposal phase to read the specific lines flagged by a finding.
    start_line is 1-based. end_line=0 means read to EOF.
    Returns content with line numbers for easy diff drafting.
    Max 500 KB per call; use start_line/end_line to read a slice of large files.
    """
    if not file_path or not file_path.strip():
        return {"success": False, "error": "file_path cannot be empty"}

    fpath = Path(file_path.strip())
    if not fpath.exists():
        return {"success": False, "error": f"File does not exist: {file_path}"}
    if not fpath.is_file():
        return {"success": False, "error": f"Path is not a file: {file_path}"}

    try:
        size = fpath.stat().st_size
        if size > _MAX_FILE_BYTES:
            # Still allow reading a slice
            if start_line == 1 and end_line == 0:
                return {
                    "success": False,
                    "error": f"File is {size} bytes — too large to read whole. Use start_line/end_line to read a slice.",
                    "size_bytes": size,
                }

        raw = fpath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {"success": False, "error": f"Failed to read file: {e!s}"}

    all_lines = raw.splitlines()
    total_lines = len(all_lines)

    # Apply line range (1-based, inclusive)
    s = max(1, start_line) - 1  # convert to 0-based index
    e = (end_line if end_line and end_line > 0 else total_lines)
    e = min(e, total_lines)

    slice_lines = all_lines[s:e]
    numbered = "\n".join(f"{s + i + 1:>6}  {line}" for i, line in enumerate(slice_lines))

    return {
        "success": True,
        "file_path": str(fpath),
        "total_lines": total_lines,
        "start_line": s + 1,
        "end_line": s + len(slice_lines),
        "content": numbered,
    }


@register_tool(sandbox_execution=False)
def search_files_local(
    path: str,
    pattern: str,
    file_glob: str = "",
) -> dict[str, Any]:
    """Search file contents by regex pattern across a directory tree.

    Used in the fix proposal phase to find all callers or usages of a vulnerable
    function before writing a fix, so the diff addresses every call site.
    Returns matching lines with file path and line number.
    Max 500 results returned.
    """
    if not path or not path.strip():
        return {"success": False, "error": "path cannot be empty"}
    if not pattern or not pattern.strip():
        return {"success": False, "error": "pattern cannot be empty"}

    root = Path(path.strip())
    if not root.exists():
        return {"success": False, "error": f"Path does not exist: {path}"}

    try:
        regex = re.compile(pattern.strip())
    except re.error as exc:
        return {"success": False, "error": f"Invalid regex pattern: {exc!s}"}

    glob_pat = file_glob.strip() if file_glob and file_glob.strip() else "**/*"

    matches: list[dict[str, Any]] = []
    try:
        for fpath in sorted(root.glob(glob_pat)):
            if not fpath.is_file():
                continue
            # Skip binary-ish files
            try:
                if fpath.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            for lineno, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    matches.append({
                        "file": str(fpath.relative_to(root)),
                        "line": lineno,
                        "content": line.rstrip(),
                    })
                    if len(matches) >= _MAX_SEARCH_RESULTS:
                        return {
                            "success": True,
                            "root": str(root),
                            "pattern": pattern,
                            "count": len(matches),
                            "matches": matches,
                            "truncated": True,
                            "note": f"Capped at {_MAX_SEARCH_RESULTS} results — narrow file_glob or pattern",
                        }
    except Exception as e:
        return {"success": False, "error": f"Search failed: {e!s}"}

    return {
        "success": True,
        "root": str(root),
        "pattern": pattern,
        "count": len(matches),
        "matches": matches,
        "truncated": False,
    }
