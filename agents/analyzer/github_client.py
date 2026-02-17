"""
Analyzer Agent - GitHub File Reader
====================================
Reads source files from the repository via the GitHub MCP Server.
Subset of scanner's github_client.py - only needs read operations.
"""

import json
import sys
import os

# Add MCP server to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "mcp-servers", "github"))

from server import github_read_file, ReadFileInput
from config import GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO, MAX_FILE_SIZE


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

    if result.get("size", 0) > MAX_FILE_SIZE:
        print(f"  [~] Skipping {file_path} ({result['size']} bytes > {MAX_FILE_SIZE} limit)")
        return None

    return result


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
