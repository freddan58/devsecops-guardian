"""
Quick test script for GitHub MCP Server tools.
Tests read operations against the devsecops-guardian repo.

Usage:
    export GITHUB_TOKEN=ghp_your_token_here
    python test_tools.py
"""

import asyncio
import json
import os
import sys

# Add parent to path so we can import server
sys.path.insert(0, os.path.dirname(__file__))

from server import (
    github_read_file,
    github_list_files,
    ReadFileInput,
    ListFilesInput,
)

OWNER = "freddan58"
REPO = "devsecops-guardian"


async def test_list_files(token: str):
    """Test listing files in demo-app directory."""
    print("\n=== Test: github_list_files (demo-app/) ===")
    params = ListFilesInput(token=token, owner=OWNER, repo=REPO, path="demo-app")
    result = json.loads(await github_list_files(params))

    if "error" in result:
        print(f"  ERROR: {result['error']}")
        return False

    print(f"  Found {result['count']} entries in demo-app/")
    for entry in result["entries"]:
        print(f"    [{entry['type']}] {entry['name']}")
    return True


async def test_read_file(token: str):
    """Test reading a vulnerable file."""
    print("\n=== Test: github_read_file (demo-app/routes/accounts.js) ===")
    params = ReadFileInput(
        token=token, owner=OWNER, repo=REPO, path="demo-app/routes/accounts.js"
    )
    result = json.loads(await github_read_file(params))

    if "error" in result:
        print(f"  ERROR: {result['error']}")
        return False

    content = result["content"]
    print(f"  File: {result['path']} ({result['size']} bytes)")
    print(f"  SHA: {result['sha']}")
    print(f"  Contains SQL injection: {'WHERE id = ${id}' in content or 'WHERE id = $' in content}")
    print(f"  First 200 chars:\n    {content[:200]}...")
    return True


async def main():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("ERROR: Set GITHUB_TOKEN environment variable")
        print("  PowerShell: $env:GITHUB_TOKEN = 'ghp_your_token'")
        print("  Bash: export GITHUB_TOKEN=ghp_your_token")
        sys.exit(1)

    print(f"Testing GitHub MCP Server against {OWNER}/{REPO}")
    print(f"Token: {token[:8]}...{token[-4:]}")

    results = []
    results.append(await test_list_files(token))
    results.append(await test_read_file(token))

    print(f"\n=== Results: {sum(results)}/{len(results)} tests passed ===")


if __name__ == "__main__":
    asyncio.run(main())
