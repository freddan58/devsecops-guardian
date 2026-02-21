"""
Foundry Agent Service client wrapper.
Registers and manages agents in Microsoft Foundry.

Uses azure-ai-projects SDK to connect to the Foundry endpoint
and register agents with their instructions and tools.
"""

import os
from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential


def get_foundry_client() -> AIProjectClient:
    """Create and return a Foundry AIProjectClient.

    Uses DefaultAzureCredential (az login) for authentication.
    Falls back to FOUNDRY_ENDPOINT env var or the hackathon project endpoint.
    """
    endpoint = os.getenv(
        "FOUNDRY_ENDPOINT",
        "https://devsecops-guardian-hackaton-etec.services.ai.azure.com"
        "/api/projects/devsecops-guardian-hackaton-etech",
    )
    return AIProjectClient(
        endpoint=endpoint,
        credential=DefaultAzureCredential(),
    )


def register_agent(client: AIProjectClient, name: str, instructions: str,
                    description: str = "", tools=None):
    """Register an agent in Foundry Agent Service.

    Args:
        client: AIProjectClient instance.
        name: Agent display name.
        instructions: System prompt / instructions for the agent.
        description: Short description of the agent's role.
        tools: Optional list of ToolDefinition objects.

    Returns:
        Agent object with .id attribute.
    """
    model = os.getenv("MODEL_DEPLOYMENT", "gpt-4.1-mini")
    agent = client.agents.create_agent(
        model=model,
        name=name,
        description=description,
        instructions=instructions,
        tools=tools or [],
    )
    return agent
