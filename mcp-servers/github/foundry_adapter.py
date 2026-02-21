"""
Foundry MCP Adapter — HTTP wrapper for the GitHub MCP Server.

Exposes the FastMCP server tools as HTTP endpoints compatible with
Foundry Agent Service Remote Tool integration.

Usage:
    uvicorn foundry_adapter:app --host 0.0.0.0 --port 8001

Endpoints:
    GET  /mcp/tools              — List all available MCP tools
    POST /mcp/tools/{tool_name}  — Invoke a specific tool
    GET  /health                 — Health check
"""

import json
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from server import mcp as mcp_server

app = FastAPI(
    title="DevSecOps Guardian — GitHub MCP Server (HTTP Adapter)",
    description="HTTP adapter exposing GitHub MCP tools for Foundry Agent Service integration",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "github-mcp-adapter"}


@app.get("/mcp/tools")
async def list_tools():
    """List all available MCP tools with their schemas.

    Returns the tool definitions that Foundry Agent Service can discover
    and use for agent-tool integration.
    """
    tools = mcp_server.list_tools()
    return {
        "server": "github_mcp",
        "tool_count": len(tools),
        "tools": [
            {
                "name": t.name,
                "description": t.description or "",
            }
            for t in tools
        ],
    }


@app.post("/mcp/tools/{tool_name}")
async def call_tool(tool_name: str, request: dict):
    """Invoke a specific MCP tool by name.

    Args:
        tool_name: The MCP tool name (e.g., 'github_read_file').
        request: JSON body with 'arguments' dict matching the tool's schema.

    Returns:
        JSON with the tool execution result.
    """
    try:
        arguments = request.get("arguments", {})
        result = await mcp_server.call_tool(tool_name, arguments)
        return {"tool": tool_name, "result": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
