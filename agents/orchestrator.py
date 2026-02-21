"""
Multi-Agent Orchestrator using Microsoft Agent Framework (Semantic Kernel).

Defines the Scanner -> Analyzer -> Fixer -> Risk Profiler -> Compliance
workflow as a SequentialOrchestration pipeline using agents registered
in Microsoft Foundry Agent Service.

This module demonstrates Microsoft Agent Framework integration:
- AzureAIAgent: Wraps each Foundry-registered agent as a Semantic Kernel agent
- SequentialOrchestration: Chains agents in a defined pipeline order
- CoreRuntime: Manages agent execution and message passing

Usage:
    python orchestrator.py

Note: The production pipeline (api/pipeline.py) runs agents as async
subprocesses for reliability. This orchestrator provides an alternative
entry point demonstrating the Agent Framework pattern.
"""

import asyncio
import os
import sys

from azure.ai.projects.aio import AIProjectClient
from azure.identity.aio import DefaultAzureCredential
from semantic_kernel.agents import AzureAIAgent, SequentialOrchestration
from semantic_kernel.agents.runtime import InProcessRuntime


FOUNDRY_ENDPOINT = os.getenv(
    "FOUNDRY_ENDPOINT",
    "https://devsecops-guardian-hackaton-etec.services.ai.azure.com"
    "/api/projects/devsecops-guardian-hackaton-etech",
)

# Agent names as registered in Foundry (must match register_all_agents.py)
AGENT_NAMES = [
    "SecurityScanner",
    "VulnerabilityAnalyzer",
    "SecurityFixer",
    "RiskProfiler",
    "ComplianceReporter",
]


async def get_foundry_agents(client: AIProjectClient) -> dict:
    """Retrieve all registered agents from Foundry by name.

    Returns:
        Dict mapping agent name to agent definition object.
    """
    agents_map = {}
    agent_list = client.agents.list_agents()
    async for agent in agent_list:
        if agent.name in AGENT_NAMES:
            agents_map[agent.name] = agent
    return agents_map


async def run_orchestrated_pipeline(task_description: str):
    """Execute the DevSecOps Guardian pipeline using Semantic Kernel orchestration.

    Creates AzureAIAgent wrappers for each Foundry agent and chains them
    in a SequentialOrchestration pipeline.

    Args:
        task_description: Description of the security scan task to execute.
    """
    credential = DefaultAzureCredential()
    async with AIProjectClient(
        endpoint=FOUNDRY_ENDPOINT, credential=credential
    ) as client:
        # Retrieve registered agents from Foundry
        print("Retrieving agents from Foundry Agent Service...")
        foundry_agents = await get_foundry_agents(client)

        if len(foundry_agents) < len(AGENT_NAMES):
            missing = set(AGENT_NAMES) - set(foundry_agents.keys())
            print(f"WARNING: Missing agents in Foundry: {missing}")
            print("Run register_all_agents.py first to register all agents.")

        # Create Semantic Kernel AzureAIAgent wrappers
        sk_agents = []
        for name in AGENT_NAMES:
            if name in foundry_agents:
                agent = AzureAIAgent(
                    client=client,
                    definition=foundry_agents[name],
                )
                sk_agents.append(agent)
                print(f"  [OK] {name} loaded (ID: {foundry_agents[name].id})")

        if not sk_agents:
            print("ERROR: No agents available. Cannot run pipeline.")
            return

        # Build sequential orchestration pipeline
        pipeline = SequentialOrchestration(
            members=sk_agents,
            name="DevSecOps Guardian Pipeline",
            description=(
                "Sequential security pipeline: Scanner detects vulnerabilities, "
                "Analyzer eliminates false positives, Fixer generates code fixes, "
                "RiskProfiler scores OWASP risks, ComplianceReporter maps to PCI-DSS 4.0"
            ),
        )

        print(f"\nPipeline created with {len(sk_agents)} agents")
        print(f"Orchestration: {' -> '.join(AGENT_NAMES[:len(sk_agents)])}")
        print(f"\nTask: {task_description}")
        print("=" * 60)

        # Execute the orchestration
        runtime = InProcessRuntime()
        runtime.start()

        try:
            result = await pipeline.invoke(
                task=task_description,
                runtime=runtime,
            )
            print("\n" + "=" * 60)
            print("Pipeline completed!")
            print(f"Result: {result.value}")
        finally:
            await runtime.stop_when_idle()

        # Cleanup: delete agent threads (not the agents themselves)
        for agent in sk_agents:
            await agent.client.agents.delete_agent(agent.id)


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
