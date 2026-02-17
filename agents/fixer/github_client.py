"""
Fixer Agent - GitHub Client
============================
Read and write operations via the GitHub MCP Server.
Reads source files (to get SHA + content for updates),
creates branches, commits fixes, and creates draft PRs.
"""

import json
import sys
import os

# Add MCP server to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "mcp-servers", "github"))

from server import (
    github_read_file, ReadFileInput,
    github_create_branch, CreateBranchInput,
    github_create_or_update_file, CreateOrUpdateFileInput,
    github_create_pr, CreatePRInput,
)
from config import GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO, MAX_FILE_SIZE


async def read_file_content(file_path: str, ref: str = None) -> dict | None:
    """Read a single file's content from the repo.

    Returns {path, content, sha, size} or None on error.
    The SHA is needed for updating the file later.
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


async def create_branch(branch_name: str, from_branch: str = "main") -> dict | None:
    """Create a new branch from the specified source branch.

    Returns {success, branch, sha, from_branch} or None on error.
    """
    params = CreateBranchInput(
        token=GITHUB_TOKEN,
        owner=GITHUB_OWNER,
        repo=GITHUB_REPO,
        branch_name=branch_name,
        from_branch=from_branch,
    )
    result = json.loads(await github_create_branch(params))

    if "error" in result:
        # Branch may already exist - not necessarily fatal
        print(f"  [!] Branch creation: {result['error']}")
        return None

    return result


async def update_file(
    file_path: str,
    content: str,
    message: str,
    branch: str,
    sha: str,
) -> dict | None:
    """Update an existing file on a branch.

    Args:
        file_path: Path to the file in the repo.
        content: New file content (plain text).
        message: Commit message.
        branch: Branch to commit to.
        sha: SHA of the file being replaced (from read_file_content).

    Returns {success, path, branch, commit_sha, commit_message} or None on error.
    """
    params = CreateOrUpdateFileInput(
        token=GITHUB_TOKEN,
        owner=GITHUB_OWNER,
        repo=GITHUB_REPO,
        path=file_path,
        content=content,
        message=message,
        branch=branch,
        sha=sha,
    )
    result = json.loads(await github_create_or_update_file(params))

    if "error" in result:
        print(f"  [!] File update error: {result['error']}")
        return None

    return result


async def create_pull_request(
    title: str,
    body: str,
    head_branch: str,
    base_branch: str = "main",
    draft: bool = True,
) -> dict | None:
    """Create a draft Pull Request.

    Args:
        title: PR title (e.g., 'fix: remediate SQL injection in accounts.js')
        body: PR description with vulnerability details and fix explanation.
        head_branch: Source branch with changes.
        base_branch: Target branch to merge into.
        draft: Create as draft PR (default: True for human review).

    Returns {success, pr_number, html_url, title, draft, state, created_at} or None on error.
    """
    params = CreatePRInput(
        token=GITHUB_TOKEN,
        owner=GITHUB_OWNER,
        repo=GITHUB_REPO,
        title=title,
        body=body,
        head=head_branch,
        base=base_branch,
        draft=draft,
    )
    result = json.loads(await github_create_pr(params))

    if "error" in result:
        print(f"  [!] PR creation error: {result['error']}")
        return None

    return result
