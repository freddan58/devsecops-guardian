"""
Register all 5 DevSecOps Guardian agents in Foundry Agent Service.

Run once:
    python register_all_agents.py

This registers the agents in the Foundry portal so they appear as managed
agents in the Azure AI Studio / Foundry UI.

Also registers the GitHub MCP Server as an OpenAPI tool available to
the SecurityFixer agent for creating branches, PRs, and reading code.
"""

import os
import sys
from foundry_client import get_foundry_client, register_agent
from azure.ai.agents.models import OpenApiTool, OpenApiAnonymousAuthDetails

AGENTS_CONFIG = [
    {
        "name": "SecurityScanner",
        "description": "LLM-based code vulnerability detection agent",
        "instructions": (
            "You are a security scanner agent that analyzes source code for vulnerabilities. "
            "You scan code files using LLM reasoning (not regex) to detect: SQL injection, XSS, "
            "SSRF, broken authentication, IDOR, hardcoded secrets, insecure crypto, business "
            "logic flaws, missing input validation, and IaC misconfigurations.\n\n"
            "Output: JSON array of findings with file, line, CWE code, severity, description, "
            "and evidence."
        ),
    },
    {
        "name": "VulnerabilityAnalyzer",
        "description": "Contextual false positive elimination agent",
        "instructions": (
            "You are a vulnerability analyzer agent that performs contextual false positive "
            "elimination. For each finding from the Scanner, you reason about: endpoint exposure "
            "(public vs authenticated), input sanitization upstream, authentication/authorization "
            "in code path, data sensitivity (PCI/PII), and actual exploitability given the "
            "application architecture.\n\n"
            "Output: Confirmed/false_positive verdict with exploitability score (0-100) "
            "and reasoning."
        ),
    },
    {
        "name": "SecurityFixer",
        "description": "Automated remediation code generation agent",
        "instructions": (
            "You are a security fixer agent that generates code fixes for confirmed "
            "vulnerabilities. For each confirmed finding, you: read the vulnerable code, "
            "generate a framework-aware fix, create a draft Pull Request on a security/ "
            "branch, and add PR comments explaining the fix rationale.\n\n"
            "Output: Fixed code, fix explanation, PR branch name, and fix strategy."
        ),
    },
    {
        "name": "RiskProfiler",
        "description": "OWASP Top 10 risk assessment agent",
        "instructions": (
            "You are a risk profiler agent that generates OWASP-based risk profiles. "
            "You analyze all confirmed findings and map them to OWASP Top 10 categories, "
            "calculate risk scores per category, and produce a radar chart data structure.\n\n"
            "Output: OWASP risk profile with category scores and overall risk level."
        ),
    },
    {
        "name": "ComplianceReporter",
        "description": "PCI-DSS 4.0 audit report generation agent",
        "instructions": (
            "You are a compliance reporter agent that generates PCI-DSS 4.0 audit-ready "
            "reports. You map each finding to regulatory controls (PCI-DSS 4.0 Req 6.2.4, "
            "6.3.1, 6.4.1, 8.3), build evidence trails (detected -> analyzed -> fix PR -> "
            "merged -> verified), and produce compliance posture scores.\n\n"
            "Output: Compliance report with regulatory mappings, evidence chains, and "
            "compliance scores."
        ),
    },
]


# GitHub MCP Server OpenAPI spec for Foundry tool registration
MCP_SERVER_URL = os.getenv(
    "MCP_SERVER_URL",
    "https://ca-api-gateway.agreeablesand-6566841b.eastus.azurecontainerapps.io/mcp",
)

GITHUB_MCP_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "GitHub MCP Server",
        "description": "GitHub MCP Server with 9 tools for code reading, PR creation, and review",
        "version": "1.0.0",
    },
    "servers": [{"url": MCP_SERVER_URL}],
    "paths": {
        "/tools/github_read_file": {
            "post": {
                "operationId": "github_read_file",
                "summary": "Read a file from GitHub repository",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "File content"}},
            }
        },
        "/tools/github_list_files": {
            "post": {
                "operationId": "github_list_files",
                "summary": "List files in a repository directory",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "File listing"}},
            }
        },
        "/tools/github_create_branch": {
            "post": {
                "operationId": "github_create_branch",
                "summary": "Create a new branch in the repository",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "Branch created"}},
            }
        },
        "/tools/github_create_or_update_file": {
            "post": {
                "operationId": "github_create_or_update_file",
                "summary": "Create or update a file in the repository",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "File created/updated"}},
            }
        },
        "/tools/github_create_pr": {
            "post": {
                "operationId": "github_create_pr",
                "summary": "Create a Pull Request",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "PR created"}},
            }
        },
        "/tools/github_post_pr_comment": {
            "post": {
                "operationId": "github_post_pr_comment",
                "summary": "Post a comment on a Pull Request",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "Comment posted"}},
            }
        },
    },
}


def _get_mcp_tool():
    """Create OpenAPI tool definition for the GitHub MCP Server."""
    return OpenApiTool(
        name="github_mcp_server",
        description="GitHub MCP Server with tools for reading files, creating branches, PRs, and posting comments",
        spec=GITHUB_MCP_OPENAPI_SPEC,
        auth=OpenApiAnonymousAuthDetails(),
    )


def main():
    print("Connecting to Foundry Agent Service...")
    try:
        client = get_foundry_client()
    except Exception as e:
        print(f"Failed to connect to Foundry: {e}")
        sys.exit(1)

    # Build MCP tool definitions for Fixer agent
    mcp_tool_defs = []
    try:
        mcp_tool = _get_mcp_tool()
        mcp_tool_defs = mcp_tool.definitions
        print(f"[OK] GitHub MCP OpenAPI tool definition created ({len(mcp_tool_defs)} definitions)")
    except Exception as e:
        print(f"[WARN] Could not create MCP tool definition: {e}")

    print("\nRegistering agents in Foundry Agent Service...\n")

    registered = []
    for config in AGENTS_CONFIG:
        try:
            # Attach MCP tools to SecurityFixer agent
            tools = mcp_tool_defs if config["name"] == "SecurityFixer" and mcp_tool_defs else None

            agent = register_agent(
                client,
                name=config["name"],
                instructions=config["instructions"],
                description=config["description"],
                tools=tools,
            )
            tool_info = " + MCP tools" if tools else ""
            print(f"  [OK] {config['name']} registered (ID: {agent.id}){tool_info}")
            registered.append({"name": config["name"], "id": agent.id})
        except Exception as e:
            print(f"  [FAIL] {config['name']}: {e}")

    print(f"\n{len(registered)}/{len(AGENTS_CONFIG)} agents registered successfully!")
    if registered:
        print("\nAgent IDs:")
        for r in registered:
            print(f"  {r['name']}: {r['id']}")
        print("\nView them in the Foundry portal: https://ai.azure.com")

    return registered


if __name__ == "__main__":
    main()
