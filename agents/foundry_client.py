"""
Foundry Agent Service client wrapper (Responses API).

Uses azure-ai-projects v2 SDK to connect to Microsoft Foundry and manage
agents via the new Responses API protocol (not the deprecated Assistants API).

Agents created with this module appear in the main "Agents" section of the
Azure AI Foundry portal (not under "Classic Agents").
"""

import os
from azure.ai.projects import AIProjectClient
from azure.ai.projects.models import PromptAgentDefinition
from azure.identity import DefaultAzureCredential


FOUNDRY_ENDPOINT = os.getenv(
    "FOUNDRY_ENDPOINT",
    "https://devsecops-guardian-hackaton-etec.services.ai.azure.com"
    "/api/projects/devsecops-guardian-hackaton-etech",
)

MODEL_DEPLOYMENT = os.getenv("MODEL_DEPLOYMENT", "gpt-4.1-mini")


def get_foundry_client() -> AIProjectClient:
    """Create and return a Foundry AIProjectClient (v2, Responses API).

    Uses DefaultAzureCredential (az login) for authentication.
    """
    return AIProjectClient(
        endpoint=FOUNDRY_ENDPOINT,
        credential=DefaultAzureCredential(),
    )


def register_agent(client: AIProjectClient, name: str, instructions: str,
                    description: str = "", tools=None):
    """Register an agent in Foundry Agent Service (Responses API).

    Creates a new-style Foundry agent using PromptAgentDefinition,
    which appears in the main Agents section of the portal.

    Args:
        client: AIProjectClient v2 instance.
        name: Agent display name (used as agent_name identifier).
        instructions: System prompt / instructions for the agent.
        description: Short description of the agent's role.
        tools: Optional list of Tool objects for the agent definition.

    Returns:
        AgentDetails object with .name attribute.
    """
    definition = PromptAgentDefinition(
        model=MODEL_DEPLOYMENT,
        instructions=instructions,
        tools=tools or [],
    )

    agent = client.agents.create(
        name=name,
        definition=definition,
        description=description,
    )
    return agent


def get_openai_client(client: AIProjectClient):
    """Get an OpenAI client pre-configured for this Foundry project.

    The returned client supports the Responses API:
    - openai_client.responses.create(...)
    - openai_client.conversations.create(...)

    Args:
        client: AIProjectClient v2 instance.

    Returns:
        openai.OpenAI client configured for the Foundry endpoint.
    """
    return client.get_openai_client()
