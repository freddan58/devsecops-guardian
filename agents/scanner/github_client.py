"""
Scanner Agent - GitHub Integration
====================================
Uses the GitHub MCP Server tools to read files from the repository.
This module wraps the MCP tools for direct use by the scanner.
"""

import json
import sys
import os

# Add MCP server to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "mcp-servers", "github"))

from server import (
    github_read_file,
    github_list_files,
    github_list_pr_files,
    github_read_pr_diff,
    ReadFileInput,
    ListFilesInput,
    ListPRFilesInput,
    ReadPRDiffInput,
)
from config import GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO, SCAN_EXTENSIONS, SKIP_DIRS, SKIP_FILES, MAX_FILE_SIZE


async def list_repo_files(path: str = "", ref: str = None) -> list[dict]:
    """Recursively list all scannable files in a repo directory.
    
    Returns list of {name, path, type, size} for files matching SCAN_EXTENSIONS.
    """
    params = ListFilesInput(
        token=GITHUB_TOKEN,
        owner=GITHUB_OWNER,
        repo=GITHUB_REPO,
        path=path,
        ref=ref,
    )
    result = json.loads(await github_list_files(params))

    if "error" in result:
        print(f"  [!] Error listing {path}: {result['error']}")
        return []

    files = []
    for entry in result.get("entries", []):
        name = entry["name"]

        # Skip excluded directories
        if entry["type"] == "dir":
            if name in SKIP_DIRS:
                continue
            # Recurse into subdirectories
            sub_files = await list_repo_files(entry["path"], ref)
            files.extend(sub_files)
        else:
            # Check extension and skip excluded files
            if name in SKIP_FILES:
                continue
            _, ext = os.path.splitext(name)
            if ext.lower() in SCAN_EXTENSIONS:
                files.append(entry)

    return files


async def read_file_content(file_path: str, ref: str = None) -> dict | None:
    """Read a single file's content from the repo.
    
    Returns {path, content, sha, size} or None on error.
    """
    params = ReadFileInput(
        token=GITHUB_TOKEN,
        owner=GITHUB_OWNER,
        repo=GITHUB_REPO,
        path=file_path,
        ref=ref,
    )
    result = json.loads(await github_read_file(params))

    if "error" in result:
        print(f"  [!] Error reading {file_path}: {result['error']}")
        return None

    # Skip files that are too large
    if result.get("size", 0) > MAX_FILE_SIZE:
        print(f"  [~] Skipping {file_path} ({result['size']} bytes > {MAX_FILE_SIZE} limit)")
        return None

    return result


async def get_pr_changed_files(pr_number: int) -> list[dict]:
    """Get list of files changed in a PR with their patches.
    
    Returns list of {filename, status, additions, deletions, patch}.
    """
    params = ListPRFilesInput(
        token=GITHUB_TOKEN,
        owner=GITHUB_OWNER,
        repo=GITHUB_REPO,
        pr_number=pr_number,
    )
    result = json.loads(await github_list_pr_files(params))

    if "error" in result:
        print(f"  [!] Error reading PR #{pr_number} files: {result['error']}")
        return []

    # Filter to scannable files
    scannable = []
    for f in result.get("files", []):
        _, ext = os.path.splitext(f["filename"])
        if ext.lower() in SCAN_EXTENSIONS and f["status"] != "removed":
            scannable.append(f)

    return scannable


async def read_multiple_files(file_paths: list[str], ref: str = None) -> list[dict]:
    """Read multiple files from the repo.
    
    Returns list of {path, content, sha, size} for successfully read files.
    """
    results = []
    for fp in file_paths:
        data = await read_file_content(fp, ref)
        if data and data.get("content"):
            results.append(data)
    return results
