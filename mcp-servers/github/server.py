"""
GitHub MCP Server for DevSecOps Guardian
=========================================
Provides tools for AI agents to interact with GitHub repositories:
- Read files and directories from repos
- Read PR diffs for security scanning
- Create branches and draft PRs with fixes
- Post review comments on PRs

Runs as an MCP server that Foundry agents connect to.
"""

import json
import base64
from typing import Optional, List

import httpx
from pydantic import BaseModel, Field, ConfigDict
from mcp.server.fastmcp import FastMCP

# ============================================================
# Configuration
# ============================================================

GITHUB_API_BASE = "https://api.github.com"
DEFAULT_TIMEOUT = 30.0

# Initialize MCP Server
mcp = FastMCP("github_mcp")

# ============================================================
# HTTP Client
# ============================================================

def _get_headers(token: str) -> dict:
    """Build GitHub API headers with authentication."""
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def _github_request(
    method: str,
    path: str,
    token: str,
    json_body: Optional[dict] = None,
    params: Optional[dict] = None,
) -> dict:
    """Make an authenticated request to the GitHub API."""
    url = f"{GITHUB_API_BASE}{path}"
    headers = _get_headers(token)

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            json=json_body,
            params=params,
        )

        if response.status_code == 404:
            return {"error": f"Not found: {path}. Check owner/repo/path are correct."}
        if response.status_code == 403:
            return {"error": "Permission denied. Check your token has the required scopes."}
        if response.status_code == 422:
            detail = response.json().get("message", "Validation failed")
            return {"error": f"Validation error: {detail}"}
        if response.status_code >= 400:
            return {"error": f"GitHub API error {response.status_code}: {response.text[:500]}"}

        if response.status_code == 204:
            return {"success": True}

        return response.json()


def _handle_error(e: Exception) -> str:
    """Format errors consistently for agent consumption."""
    if isinstance(e, httpx.HTTPStatusError):
        return json.dumps({"error": f"HTTP {e.response.status_code}: {e.response.text[:300]}"})
    if isinstance(e, httpx.TimeoutException):
        return json.dumps({"error": "Request timed out. Try again."})
    return json.dumps({"error": f"{type(e).__name__}: {str(e)}"})


# ============================================================
# Input Models
# ============================================================

class ReadFileInput(BaseModel):
    """Input for reading a single file from a GitHub repository."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    token: str = Field(..., description="GitHub personal access token", min_length=1)
    owner: str = Field(..., description="Repository owner (e.g., 'freddan58')", min_length=1)
    repo: str = Field(..., description="Repository name (e.g., 'devsecops-guardian')", min_length=1)
    path: str = Field(..., description="File path relative to repo root (e.g., 'demo-app/routes/accounts.js')", min_length=1)
    ref: Optional[str] = Field(default=None, description="Branch or commit SHA (default: repo default branch)")


class ListFilesInput(BaseModel):
    """Input for listing files in a repository directory."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    token: str = Field(..., description="GitHub personal access token", min_length=1)
    owner: str = Field(..., description="Repository owner", min_length=1)
    repo: str = Field(..., description="Repository name", min_length=1)
    path: Optional[str] = Field(default="", description="Directory path (empty for repo root)")
    ref: Optional[str] = Field(default=None, description="Branch or commit SHA")


class ReadPRDiffInput(BaseModel):
    """Input for reading a Pull Request diff."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    token: str = Field(..., description="GitHub personal access token", min_length=1)
    owner: str = Field(..., description="Repository owner", min_length=1)
    repo: str = Field(..., description="Repository name", min_length=1)
    pr_number: int = Field(..., description="Pull Request number", ge=1)


class ListPRFilesInput(BaseModel):
    """Input for listing files changed in a Pull Request."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    token: str = Field(..., description="GitHub personal access token", min_length=1)
    owner: str = Field(..., description="Repository owner", min_length=1)
    repo: str = Field(..., description="Repository name", min_length=1)
    pr_number: int = Field(..., description="Pull Request number", ge=1)


class CreateBranchInput(BaseModel):
    """Input for creating a new branch."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    token: str = Field(..., description="GitHub personal access token", min_length=1)
    owner: str = Field(..., description="Repository owner", min_length=1)
    repo: str = Field(..., description="Repository name", min_length=1)
    branch_name: str = Field(..., description="New branch name (e.g., 'security/fix-sql-injection')", min_length=1)
    from_branch: Optional[str] = Field(default="main", description="Source branch to branch from")


class CreateOrUpdateFileInput(BaseModel):
    """Input for creating or updating a file in the repository."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    token: str = Field(..., description="GitHub personal access token", min_length=1)
    owner: str = Field(..., description="Repository owner", min_length=1)
    repo: str = Field(..., description="Repository name", min_length=1)
    path: str = Field(..., description="File path to create/update", min_length=1)
    content: str = Field(..., description="File content (plain text, will be base64 encoded)")
    message: str = Field(..., description="Commit message", min_length=1)
    branch: str = Field(..., description="Branch to commit to", min_length=1)
    sha: Optional[str] = Field(default=None, description="SHA of file being replaced (required for updates)")


class CreatePRInput(BaseModel):
    """Input for creating a Pull Request."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    token: str = Field(..., description="GitHub personal access token", min_length=1)
    owner: str = Field(..., description="Repository owner", min_length=1)
    repo: str = Field(..., description="Repository name", min_length=1)
    title: str = Field(..., description="PR title (e.g., 'fix: remediate SQL injection in accounts.js')", min_length=1)
    body: str = Field(..., description="PR description with vulnerability details and fix explanation")
    head: str = Field(..., description="Source branch with changes (e.g., 'security/fix-sql-injection')")
    base: Optional[str] = Field(default="main", description="Target branch to merge into")
    draft: Optional[bool] = Field(default=True, description="Create as draft PR (default: true for human review)")


class PostPRCommentInput(BaseModel):
    """Input for posting a comment on a Pull Request."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    token: str = Field(..., description="GitHub personal access token", min_length=1)
    owner: str = Field(..., description="Repository owner", min_length=1)
    repo: str = Field(..., description="Repository name", min_length=1)
    pr_number: int = Field(..., description="Pull Request number", ge=1)
    body: str = Field(..., description="Comment text (supports markdown)", min_length=1)


class GetPRInput(BaseModel):
    """Input for getting Pull Request details."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    token: str = Field(..., description="GitHub personal access token", min_length=1)
    owner: str = Field(..., description="Repository owner", min_length=1)
    repo: str = Field(..., description="Repository name", min_length=1)
    pr_number: int = Field(..., description="Pull Request number", ge=1)


# ============================================================
# Tools: Read Operations
# ============================================================

@mcp.tool(
    name="github_read_file",
    annotations={
        "title": "Read File from GitHub",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def github_read_file(params: ReadFileInput) -> str:
    """Read a single file's content from a GitHub repository.

    Returns the decoded file content. Used by Scanner and Analyzer agents
    to read source code files for security analysis.

    Args:
        params (ReadFileInput): Repository coordinates and file path.

    Returns:
        str: JSON with file content, path, size, and SHA.
    """
    try:
        query_params = {}
        if params.ref:
            query_params["ref"] = params.ref

        result = await _github_request(
            "GET",
            f"/repos/{params.owner}/{params.repo}/contents/{params.path}",
            params.token,
            params=query_params,
        )

        if "error" in result:
            return json.dumps(result)

        # Handle file content
        if isinstance(result, list):
            return json.dumps({"error": "Path is a directory, not a file. Use github_list_files instead."})

        content = ""
        if result.get("encoding") == "base64" and result.get("content"):
            content = base64.b64decode(result["content"]).decode("utf-8", errors="replace")

        return json.dumps({
            "path": result.get("path"),
            "name": result.get("name"),
            "size": result.get("size"),
            "sha": result.get("sha"),
            "content": content,
        })

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="github_list_files",
    annotations={
        "title": "List Files in Directory",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def github_list_files(params: ListFilesInput) -> str:
    """List files and directories in a repository path.

    Returns name, type (file/dir), size, and path for each entry.
    Used by agents to discover which files to scan.

    Args:
        params (ListFilesInput): Repository coordinates and directory path.

    Returns:
        str: JSON array of file/directory entries.
    """
    try:
        query_params = {}
        if params.ref:
            query_params["ref"] = params.ref

        result = await _github_request(
            "GET",
            f"/repos/{params.owner}/{params.repo}/contents/{params.path}",
            params.token,
            params=query_params,
        )

        if "error" in result:
            return json.dumps(result)

        if not isinstance(result, list):
            return json.dumps({"error": "Path is a file, not a directory. Use github_read_file instead."})

        entries = [
            {
                "name": item["name"],
                "type": item["type"],  # "file" or "dir"
                "size": item.get("size", 0),
                "path": item["path"],
            }
            for item in result
        ]

        return json.dumps({"path": params.path or "/", "count": len(entries), "entries": entries})

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="github_read_pr_diff",
    annotations={
        "title": "Read Pull Request Diff",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def github_read_pr_diff(params: ReadPRDiffInput) -> str:
    """Read the unified diff of a Pull Request.

    Returns the raw diff text showing all changes. Used by Scanner agent
    to analyze code changes in PRs for security vulnerabilities.

    Args:
        params (ReadPRDiffInput): Repository coordinates and PR number.

    Returns:
        str: JSON with PR metadata and diff content.
    """
    try:
        url = f"{GITHUB_API_BASE}/repos/{params.owner}/{params.repo}/pulls/{params.pr_number}"
        headers = _get_headers(params.token)
        headers["Accept"] = "application/vnd.github.v3.diff"

        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.get(url, headers=headers)

            if response.status_code >= 400:
                return json.dumps({"error": f"Failed to get PR diff: HTTP {response.status_code}"})

            diff_text = response.text

        # Also get PR metadata
        pr_info = await _github_request(
            "GET",
            f"/repos/{params.owner}/{params.repo}/pulls/{params.pr_number}",
            params.token,
        )

        return json.dumps({
            "pr_number": params.pr_number,
            "title": pr_info.get("title", ""),
            "state": pr_info.get("state", ""),
            "base_branch": pr_info.get("base", {}).get("ref", ""),
            "head_branch": pr_info.get("head", {}).get("ref", ""),
            "diff": diff_text,
        })

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="github_list_pr_files",
    annotations={
        "title": "List Files Changed in PR",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def github_list_pr_files(params: ListPRFilesInput) -> str:
    """List all files changed in a Pull Request with their status and patch.

    Returns filename, status (added/modified/removed), additions, deletions,
    and patch for each changed file. Used by Scanner agent to know which
    files to analyze.

    Args:
        params (ListPRFilesInput): Repository coordinates and PR number.

    Returns:
        str: JSON array of changed files with patches.
    """
    try:
        result = await _github_request(
            "GET",
            f"/repos/{params.owner}/{params.repo}/pulls/{params.pr_number}/files",
            params.token,
        )

        if isinstance(result, dict) and "error" in result:
            return json.dumps(result)

        files = [
            {
                "filename": f["filename"],
                "status": f["status"],  # added, modified, removed, renamed
                "additions": f.get("additions", 0),
                "deletions": f.get("deletions", 0),
                "changes": f.get("changes", 0),
                "patch": f.get("patch", ""),
            }
            for f in result
        ]

        return json.dumps({"pr_number": params.pr_number, "total_files": len(files), "files": files})

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="github_get_pr",
    annotations={
        "title": "Get Pull Request Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def github_get_pr(params: GetPRInput) -> str:
    """Get detailed information about a Pull Request.

    Returns PR title, state, author, branch info, merge status, timestamps.
    Used by Compliance agent to track PR lifecycle for evidence trails.

    Args:
        params (GetPRInput): Repository coordinates and PR number.

    Returns:
        str: JSON with full PR details.
    """
    try:
        result = await _github_request(
            "GET",
            f"/repos/{params.owner}/{params.repo}/pulls/{params.pr_number}",
            params.token,
        )

        if "error" in result:
            return json.dumps(result)

        return json.dumps({
            "number": result.get("number"),
            "title": result.get("title"),
            "state": result.get("state"),
            "draft": result.get("draft"),
            "merged": result.get("merged"),
            "merged_at": result.get("merged_at"),
            "created_at": result.get("created_at"),
            "updated_at": result.get("updated_at"),
            "user": result.get("user", {}).get("login"),
            "base_branch": result.get("base", {}).get("ref"),
            "head_branch": result.get("head", {}).get("ref"),
            "body": result.get("body", ""),
            "html_url": result.get("html_url"),
        })

    except Exception as e:
        return _handle_error(e)


# ============================================================
# Tools: Write Operations
# ============================================================

@mcp.tool(
    name="github_create_branch",
    annotations={
        "title": "Create Branch",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def github_create_branch(params: CreateBranchInput) -> str:
    """Create a new branch in the repository.

    Creates a branch from the HEAD of the specified source branch.
    Used by Fixer agent to create security/ branches for fix PRs.

    Args:
        params (CreateBranchInput): Repository coordinates, new branch name, source branch.

    Returns:
        str: JSON with branch creation result.
    """
    try:
        # Get the SHA of the source branch
        ref_result = await _github_request(
            "GET",
            f"/repos/{params.owner}/{params.repo}/git/ref/heads/{params.from_branch}",
            params.token,
        )

        if "error" in ref_result:
            return json.dumps({"error": f"Source branch '{params.from_branch}' not found."})

        sha = ref_result.get("object", {}).get("sha")
        if not sha:
            return json.dumps({"error": "Could not get SHA from source branch."})

        # Create the new branch
        result = await _github_request(
            "POST",
            f"/repos/{params.owner}/{params.repo}/git/refs",
            params.token,
            json_body={"ref": f"refs/heads/{params.branch_name}", "sha": sha},
        )

        if "error" in result:
            return json.dumps(result)

        return json.dumps({
            "success": True,
            "branch": params.branch_name,
            "sha": sha,
            "from_branch": params.from_branch,
        })

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="github_create_or_update_file",
    annotations={
        "title": "Create or Update File",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def github_create_or_update_file(params: CreateOrUpdateFileInput) -> str:
    """Create a new file or update an existing file in the repository.

    Content is automatically base64-encoded. For updates, provide the SHA
    of the file being replaced (get it from github_read_file).
    Used by Fixer agent to commit code fixes.

    Args:
        params (CreateOrUpdateFileInput): File path, content, commit message, branch.

    Returns:
        str: JSON with commit details.
    """
    try:
        encoded_content = base64.b64encode(params.content.encode("utf-8")).decode("utf-8")

        body = {
            "message": params.message,
            "content": encoded_content,
            "branch": params.branch,
        }

        if params.sha:
            body["sha"] = params.sha

        result = await _github_request(
            "PUT",
            f"/repos/{params.owner}/{params.repo}/contents/{params.path}",
            params.token,
            json_body=body,
        )

        if "error" in result:
            return json.dumps(result)

        return json.dumps({
            "success": True,
            "path": params.path,
            "branch": params.branch,
            "commit_sha": result.get("commit", {}).get("sha"),
            "commit_message": params.message,
        })

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="github_create_pr",
    annotations={
        "title": "Create Pull Request",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def github_create_pr(params: CreatePRInput) -> str:
    """Create a Pull Request in the repository.

    Creates a draft PR by default so developers must review before merging.
    Used by Fixer agent to submit security fixes for human review.

    Args:
        params (CreatePRInput): PR title, body, source/target branches, draft flag.

    Returns:
        str: JSON with PR number, URL, and creation details.
    """
    try:
        body = {
            "title": params.title,
            "body": params.body,
            "head": params.head,
            "base": params.base,
            "draft": params.draft,
        }

        result = await _github_request(
            "POST",
            f"/repos/{params.owner}/{params.repo}/pulls",
            params.token,
            json_body=body,
        )

        if "error" in result:
            return json.dumps(result)

        return json.dumps({
            "success": True,
            "pr_number": result.get("number"),
            "html_url": result.get("html_url"),
            "title": result.get("title"),
            "draft": result.get("draft"),
            "state": result.get("state"),
            "created_at": result.get("created_at"),
        })

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="github_post_pr_comment",
    annotations={
        "title": "Post Comment on Pull Request",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def github_post_pr_comment(params: PostPRCommentInput) -> str:
    """Post a comment on a Pull Request.

    Used by Fixer agent to add vulnerability details and fix explanations
    to PRs, and by Scanner/Analyzer to post findings summaries.

    Args:
        params (PostPRCommentInput): PR number and comment body (markdown supported).

    Returns:
        str: JSON with comment ID, URL, and creation timestamp.
    """
    try:
        result = await _github_request(
            "POST",
            f"/repos/{params.owner}/{params.repo}/issues/{params.pr_number}/comments",
            params.token,
            json_body={"body": params.body},
        )

        if "error" in result:
            return json.dumps(result)

        return json.dumps({
            "success": True,
            "comment_id": result.get("id"),
            "html_url": result.get("html_url"),
            "created_at": result.get("created_at"),
        })

    except Exception as e:
        return _handle_error(e)


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    mcp.run()
