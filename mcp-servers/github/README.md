# GitHub MCP Server

MCP (Model Context Protocol) server that provides DevSecOps Guardian agents with access to GitHub repositories.

## Tools Available

### Read Operations
| Tool | Description | Used By |
|------|------------|---------|
| `github_read_file` | Read a file's content from a repo | Scanner, Analyzer |
| `github_list_files` | List files/dirs in a path | Scanner |
| `github_read_pr_diff` | Get unified diff of a PR | Scanner |
| `github_list_pr_files` | List changed files in a PR | Scanner |
| `github_get_pr` | Get PR details and status | Compliance |

### Write Operations
| Tool | Description | Used By |
|------|------------|---------|
| `github_create_branch` | Create a security/ branch | Fixer |
| `github_create_or_update_file` | Commit file changes | Fixer |
| `github_create_pr` | Create draft PR with fix | Fixer |
| `github_post_pr_comment` | Post review comment | Fixer, Scanner |

## Setup

```bash
cd mcp-servers/github
pip install -e .
```

## Run

```bash
# stdio mode (for local agent testing)
python server.py

# Or with MCP CLI
mcp run server.py
```

## Authentication

All tools require a `token` parameter (GitHub Personal Access Token). 
The token needs these scopes:
- `repo` (full control of private repositories)
- `read:org` (if scanning org repos)

## Architecture

```
Agent (Foundry) → MCP Protocol → GitHub MCP Server → GitHub REST API
```

The server translates MCP tool calls into GitHub API requests, handling authentication, error formatting, and response normalization for agent consumption.
