"""
Multi-Agent Orchestrator using Microsoft Agent Framework.

Defines the Scanner -> Analyzer -> Fixer -> Risk Profiler -> Compliance
workflow as a chained WorkflowBuilder pipeline using agents registered
in Microsoft Foundry Agent Service (Responses API).

This module demonstrates Microsoft Agent Framework integration:
- AzureAIClient: Connects to Foundry agents via Responses API
- Agent: Wraps each client as an executable agent
- WorkflowBuilder: Chains agents in a sequential pipeline
- Workflow: Executes the complete pipeline

Usage:
    python orchestrator.py

Note: The production pipeline (api/pipeline.py) runs agents as async
subprocesses for reliability. This orchestrator provides an alternative
entry point demonstrating the Agent Framework pattern.
"""

import asyncio
import os
import sys

from agent_framework import Agent, WorkflowBuilder
from agent_framework_azure_ai import AzureAIClient
from azure.identity import DefaultAzureCredential


FOUNDRY_ENDPOINT = os.getenv(
    "FOUNDRY_ENDPOINT",
    "https://devsecops-guardian-hackaton-etec.services.ai.azure.com"
    "/api/projects/devsecops-guardian-hackaton-etech",
)

MODEL_DEPLOYMENT = os.getenv("MODEL_DEPLOYMENT", "gpt-4.1-mini")

# Agent names as registered in Foundry (must match register_all_agents.py)
AGENT_NAMES = [
    "SecurityScanner",
    "VulnerabilityAnalyzer",
    "SecurityFixer",
    "RiskProfiler",
    "ComplianceReporter",
]


def create_foundry_agents() -> list[Agent]:
    """Create Agent Framework agents backed by Foundry-registered agents.

    Each agent connects to its Foundry counterpart via AzureAIClient
    (Responses API), allowing the WorkflowBuilder to orchestrate them.

    Returns:
        List of Agent objects ready for workflow chaining.
    """
    credential = DefaultAzureCredential()
    agents = []

    for name in AGENT_NAMES:
        client = AzureAIClient(
            project_endpoint=FOUNDRY_ENDPOINT,
            agent_name=name,
            model_deployment_name=MODEL_DEPLOYMENT,
            credential=credential,
        )
        agent = Agent(
            client=client,
            name=name,
            description=f"DevSecOps Guardian {name} agent",
        )
        agents.append(agent)
        print(f"  [OK] {name} connected via Responses API")

    return agents


def build_pipeline(agents: list[Agent]):
    """Build a sequential workflow pipeline from the agent list.

    Uses WorkflowBuilder.add_chain() to create a linear pipeline:
    Scanner -> Analyzer -> Fixer -> RiskProfiler -> Compliance

    Args:
        agents: List of Agent objects in pipeline order.

    Returns:
        Workflow object ready for execution.
    """
    builder = WorkflowBuilder(
        start_executor=agents[0],
        name="DevSecOps Guardian Pipeline",
        description=(
            "Sequential security pipeline: Scanner detects vulnerabilities, "
            "Analyzer eliminates false positives, Fixer generates code fixes, "
            "RiskProfiler scores OWASP risks, ComplianceReporter maps to PCI-DSS 4.0"
        ),
        output_executors=[agents[-1]],
    )

    if len(agents) > 1:
        builder.add_chain(agents)

    return builder.build()


async def run_orchestrated_pipeline(task_description: str):
    """Execute the DevSecOps Guardian pipeline using Agent Framework orchestration.

    Args:
        task_description: Description of the security scan task to execute.
    """
    print("Creating agents from Foundry Agent Service (Responses API)...")
    agents = create_foundry_agents()

    if not agents:
        print("ERROR: No agents available. Cannot run pipeline.")
        return

    print(f"\nPipeline created with {len(agents)} agents")
    print(f"Orchestration: {' -> '.join(AGENT_NAMES[:len(agents)])}")
    print(f"\nTask: {task_description}")
    print("=" * 60)

    workflow = build_pipeline(agents)

    result = await workflow.run(message=task_description)
    print("\n" + "=" * 60)
    print("Pipeline completed!")
    print(f"Result: {result}")

    # Cleanup clients
    for agent in agents:
        if hasattr(agent, 'client') and hasattr(agent.client, 'close'):
            agent.client.close()


async def main():
    """Entry point for orchestrator demo."""
    task = (
        "Scan the repository freddan58/devsecops-guardian (demo-app/ directory) "
        "for security vulnerabilities. Analyze each finding for false positives, "
        "generate fixes for confirmed vulnerabilities, profile OWASP risks, "
        "and produce a PCI-DSS 4.0 compliance report."
    )

    if len(sys.argv) > 1:
        task = " ".join(sys.argv[1:])

    await run_orchestrated_pipeline(task)


if __name__ == "__main__":
    asyncio.run(main())
