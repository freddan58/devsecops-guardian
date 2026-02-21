"""
Register all 5 DevSecOps Guardian agents in Foundry Agent Service.

Uses the new Responses API (azure-ai-projects v2) — agents appear in the
main "Agents" section of Azure AI Foundry portal, NOT under "Classic Agents".

Registers agents with FULL system prompts (loaded from each agent's prompts.py)
so that Foundry agents can be invoked at runtime via the Responses API.

Also registers the GitHub MCP Server as a native MCPTool on the SecurityFixer
agent, demonstrating Azure MCP integration.

Run once:
    python register_all_agents.py
"""

import importlib.util
import os
import sys
from foundry_client import get_foundry_client, register_agent
from azure.ai.projects.models import MCPTool, CodeInterpreterTool, BingGroundingTool


AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_prompt(agent_subdir: str, prompt_var: str) -> str:
    """Load a system prompt from an agent's prompts.py module.

    Dynamically imports the prompts module from each agent directory
    and extracts the specified prompt variable.
    """
    prompts_path = os.path.join(AGENTS_DIR, agent_subdir, "prompts.py")
    if not os.path.exists(prompts_path):
        print(f"  [WARN] {prompts_path} not found, using fallback instructions")
        return ""
    spec = importlib.util.spec_from_file_location("prompts", prompts_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, prompt_var, "")


# Load FULL system prompts from each agent's prompts.py
# These are the same prompts used by each agent's llm_engine.py,
# ensuring Foundry agents behave identically to local agents.
AGENTS_CONFIG = [
    {
        "name": "SecurityScanner",
        "description": "LLM-based code vulnerability detection agent",
        "instructions": _load_prompt("scanner", "SCANNER_SYSTEM_PROMPT"),
    },
    {
        "name": "VulnerabilityAnalyzer",
        "description": "Contextual false positive elimination agent",
        "instructions": _load_prompt("analyzer", "ANALYZER_SYSTEM_PROMPT"),
    },
    {
        "name": "SecurityFixer",
        "description": "Automated remediation code generation agent with GitHub MCP tools",
        "instructions": _load_prompt("fixer", "FIXER_SYSTEM_PROMPT"),
    },
    {
        "name": "RiskProfiler",
        "description": "OWASP Top 10 risk assessment agent",
        "instructions": _load_prompt("risk-profiler", "RISK_PROFILER_SYSTEM_PROMPT"),
    },
    {
        "name": "ComplianceReporter",
        "description": "PCI-DSS 4.0 audit report generation agent",
        "instructions": _load_prompt("compliance", "COMPLIANCE_SYSTEM_PROMPT"),
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


def _get_agent_tools(agent_name: str, mcp_tools: list) -> list | None:
    """Build the tool list for a specific agent.

    Tool assignment:
        SecurityScanner     → CodeInterpreterTool
        VulnerabilityAnalyzer → CodeInterpreterTool
        SecurityFixer       → MCPTool (GitHub) + CodeInterpreterTool
        RiskProfiler        → BingGroundingTool
        ComplianceReporter  → BingGroundingTool
    """
    tools = []

    if agent_name in ("SecurityScanner", "VulnerabilityAnalyzer"):
        tools.append(CodeInterpreterTool())
    elif agent_name == "SecurityFixer":
        tools.append(CodeInterpreterTool())
        tools.extend(mcp_tools)
    elif agent_name in ("RiskProfiler", "ComplianceReporter"):
        tools.append(BingGroundingTool())

    return tools if tools else None


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
            tools = _get_agent_tools(config["name"], mcp_tools)

            agent = register_agent(
                client,
                name=config["name"],
                instructions=config["instructions"],
                description=config["description"],
                tools=tools,
            )
            tool_names = [type(t).__name__ for t in (tools or [])]
            tool_info = f" + tools: {tool_names}" if tool_names else ""
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
