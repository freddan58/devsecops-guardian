"""
Register all 5 DevSecOps Guardian agents in Foundry Agent Service.

Uses the new Responses API (azure-ai-projects v2) — agents appear in the
main "Agents" section of Azure AI Foundry portal, NOT under "Classic Agents".

Also registers the GitHub MCP Server as a native MCPTool on the SecurityFixer
agent, demonstrating Azure MCP integration.

Run once:
    python register_all_agents.py
"""

import os
import sys
from foundry_client import get_foundry_client, register_agent
from azure.ai.projects.models import MCPTool


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
        "description": "Automated remediation code generation agent with GitHub MCP tools",
        "instructions": (
            "You are a security fixer agent that generates code fixes for confirmed "
            "vulnerabilities. For each confirmed finding, you: read the vulnerable code, "
            "generate a framework-aware fix, create a draft Pull Request on a security/ "
            "branch, and add PR comments explaining the fix rationale.\n\n"
            "You have access to GitHub MCP tools for reading files, creating branches, "
            "creating PRs, and posting review comments.\n\n"
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


# GitHub MCP Server URL for native MCPTool integration
MCP_SERVER_URL = os.getenv(
    "MCP_SERVER_URL",
    "https://ca-api-gateway.agreeablesand-6566841b.eastus.azurecontainerapps.io/mcp",
)


def _get_mcp_tools():
    """Create native MCPTool definition for the GitHub MCP Server.

    Returns a list containing the MCPTool that connects to the
    GitHub MCP Server deployed as a Remote MCP endpoint.
    """
    return [
        MCPTool(
            server_label="github_mcp_server",
            server_url=MCP_SERVER_URL,
            require_approval="never",
        )
    ]


def main():
    print("Connecting to Foundry Agent Service (Responses API v2)...")
    try:
        client = get_foundry_client()
    except Exception as e:
        print(f"Failed to connect to Foundry: {e}")
        sys.exit(1)

    # Build MCP tool for SecurityFixer agent
    mcp_tools = []
    try:
        mcp_tools = _get_mcp_tools()
        print(f"[OK] GitHub MCP Server tool created (URL: {MCP_SERVER_URL})")
    except Exception as e:
        print(f"[WARN] Could not create MCP tool: {e}")

    print("\nRegistering agents in Foundry (Responses API)...\n")

    registered = []
    for config in AGENTS_CONFIG:
        try:
            # Attach MCP tools to SecurityFixer agent
            tools = mcp_tools if config["name"] == "SecurityFixer" and mcp_tools else None

            agent = register_agent(
                client,
                name=config["name"],
                instructions=config["instructions"],
                description=config["description"],
                tools=tools,
            )
            tool_info = " + MCP tools" if tools else ""
            print(f"  [OK] {config['name']} registered (Name: {agent.name}){tool_info}")
            registered.append({"name": config["name"], "agent_name": agent.name})
        except Exception as e:
            print(f"  [FAIL] {config['name']}: {e}")

    print(f"\n{len(registered)}/{len(AGENTS_CONFIG)} agents registered successfully!")
    if registered:
        print("\nAgents (Responses API):")
        for r in registered:
            print(f"  {r['name']}: {r['agent_name']}")
        print("\nView them in Foundry portal: https://ai.azure.com")
        print("They should appear in the main 'Agents' section (not Classic).")

    return registered


if __name__ == "__main__":
    main()
