"""
Fixer Agent - LLM Fix Generation Engine
=========================================
Sends confirmed vulnerability details + source code to Azure
OpenAI to generate production-ready security fixes.
One LLM call per finding (each fix needs focused attention).

Supports two modes:
- Foundry mode (FOUNDRY_ENDPOINT set): Routes calls through Azure AI Foundry
  for telemetry, evaluation, and monitoring via App Insights.
- Direct mode (fallback): Uses httpx to call Azure OpenAI directly.
"""

import asyncio
import json
import os
import httpx

from config import (
    AZURE_OPENAI_ENDPOINT,
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_DEPLOYMENT,
    AZURE_OPENAI_API_VERSION,
)
from prompts import FIXER_SYSTEM_PROMPT, FIXER_USER_PROMPT

# Foundry integration
FOUNDRY_ENDPOINT = os.getenv("FOUNDRY_ENDPOINT", "")
MODEL_DEPLOYMENT = os.getenv("MODEL_DEPLOYMENT", "gpt-4.1-mini")
FOUNDRY_AGENT_NAME = "SecurityFixer"

_foundry_openai = None
_tracing_initialized = False


def _init_tracing():
    """Initialize OpenTelemetry tracing + ResponsesInstrumentor for Foundry telemetry.

    Sets up:
    1. TracerProvider with AzureMonitorTraceExporter (if App Insights configured)
    2. azure-core tracing implementation for SDK-level spans
    3. ResponsesInstrumentor to capture gen_ai.* spans from responses.create()
    """
    global _tracing_initialized
    if _tracing_initialized:
        return
    _tracing_initialized = True
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        app_insights_cs = os.environ.get("APPLICATIONINSIGHTS_CONNECTION_STRING", "")
        if app_insights_cs:
            try:
                from opentelemetry.sdk._logs import LogData  # noqa: F401
            except ImportError:
                import opentelemetry.sdk._logs as _logs_mod
                class _LogDataStub:
                    pass
                _logs_mod.LogData = _LogDataStub

            from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter
            provider = TracerProvider()
            exporter = AzureMonitorTraceExporter(connection_string=app_insights_cs)
            provider.add_span_processor(SimpleSpanProcessor(exporter))
            trace.set_tracer_provider(provider)
            print(f"  [Foundry] TracerProvider + AzureMonitor exporter set for {FOUNDRY_AGENT_NAME}")

        from azure.core.settings import settings
        from azure.core.tracing.ext.opentelemetry_span import OpenTelemetrySpan
        settings.tracing_implementation = OpenTelemetrySpan

        from opentelemetry.instrumentation.openai import ResponsesInstrumentor
        ResponsesInstrumentor().instrument(enable_content_recording=True)
        print(f"  [Foundry] ResponsesInstrumentor enabled for {FOUNDRY_AGENT_NAME}")
    except ImportError as e:
        print(f"  [Foundry] Tracing setup skipped (missing dep): {e}")
    except Exception as e:
        print(f"  [Foundry] Tracing setup warning: {e}")


def _get_foundry_openai():
    """Get OpenAI client configured for Foundry project (cached)."""
    global _foundry_openai
    if _foundry_openai is None:
        _init_tracing()
        from azure.ai.projects import AIProjectClient
        from azure.identity import DefaultAzureCredential
        project = AIProjectClient(
            endpoint=FOUNDRY_ENDPOINT,
            credential=DefaultAzureCredential(),
        )
        _foundry_openai = project.get_openai_client()
        print(f"  [Foundry] OpenAI client initialized for {FOUNDRY_AGENT_NAME}")
    return _foundry_openai


def _get_language(file_path: str) -> str:
    """Infer language from file extension for code block formatting."""
    ext_map = {
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".py": "python",
        ".java": "java",
        ".cs": "csharp",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
    }
    _, ext = os.path.splitext(file_path)
    return ext_map.get(ext.lower(), "text")


async def _call_llm(messages: list[dict]) -> str:
    """Call LLM via Foundry project or direct Azure OpenAI."""
    if FOUNDRY_ENDPOINT:
        try:
            return await _call_via_foundry(messages)
        except Exception as e:
            print(f"  [!] Foundry call failed ({e}), falling back to direct Azure OpenAI")
            return await _call_direct(messages)
    return await _call_direct(messages)


async def _call_via_foundry(messages: list[dict]) -> str:
    """Call LLM through Foundry Responses API (enables telemetry + evaluation).

    Uses model=MODEL_DEPLOYMENT with instructions=system_prompt so that:
    - The call routes through the Foundry endpoint for telemetry/App Insights
    - ResponsesInstrumentor generates gen_ai spans for the Operate tab
    - The agent's system prompt is passed via the instructions parameter
    """
    system_parts = [m["content"] for m in messages if m["role"] == "system"]
    user_parts = [m["content"] for m in messages if m["role"] == "user"]
    system_prompt = "\n\n".join(system_parts) if system_parts else None
    user_prompt = "\n\n".join(user_parts)

    def _sync_call():
        client = _get_foundry_openai()
        response = client.responses.create(
            model=MODEL_DEPLOYMENT,
            instructions=system_prompt,
            input=[{"role": "user", "content": user_prompt}],
            text={"format": {"type": "json_object"}},
        )
        print(f"  [Foundry] {FOUNDRY_AGENT_NAME} responded via Responses API (model={MODEL_DEPLOYMENT})")
        return response.output_text

    return await asyncio.to_thread(_sync_call)


async def _call_direct(messages: list[dict]) -> str:
    """Direct Azure OpenAI call via httpx (fallback when Foundry not configured)."""
    url = (
        f"{AZURE_OPENAI_ENDPOINT.rstrip('/')}"
        f"/openai/deployments/{AZURE_OPENAI_DEPLOYMENT}"
        f"/chat/completions?api-version={AZURE_OPENAI_API_VERSION}"
    )

    headers = {
        "Content-Type": "application/json",
        "api-key": AZURE_OPENAI_API_KEY,
    }

    body = {
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 16000,
        "response_format": {"type": "json_object"},
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(url, headers=headers, json=body)

        if response.status_code != 200:
            raise RuntimeError(
                f"Azure OpenAI API error {response.status_code}: {response.text[:500]}"
            )

        data = response.json()
        return data["choices"][0]["message"]["content"]


def _parse_fix(raw_response: str) -> dict | None:
    """Parse LLM response into a fix dict. Returns None on failure."""
    try:
        parsed = json.loads(raw_response)

        if not isinstance(parsed, dict):
            print(f"  [!] Unexpected response type: {type(parsed)}")
            return None

        # Required: fixed_code
        if "fixed_code" not in parsed or not parsed["fixed_code"]:
            print("  [!] LLM response missing 'fixed_code'")
            return None

        return {
            "fixed_code": parsed["fixed_code"],
            "fix_summary": parsed.get("fix_summary", "Security fix applied"),
            "fix_details": parsed.get("fix_details", ""),
            "lines_changed": parsed.get("lines_changed", ""),
        }

    except json.JSONDecodeError as e:
        print(f"  [!] Failed to parse LLM response as JSON: {e}")
        print(f"  [!] Raw response: {raw_response[:500]}")
        return None


async def generate_fix(finding: dict, source_code: str) -> dict | None:
    """Generate a security fix for a single confirmed finding.

    Args:
        finding: Merged finding dict from analyzer output.
        source_code: Current file content from GitHub.

    Returns:
        Fix dict with {fixed_code, fix_summary, fix_details, lines_changed}
        or None on failure.
    """
    language = _get_language(finding.get("file", ""))

    user_prompt = FIXER_USER_PROMPT.format(
        scan_id=finding.get("scan_id", ""),
        anlz_id=finding.get("anlz_id", ""),
        vulnerability=finding.get("vulnerability", ""),
        cwe=finding.get("cwe", ""),
        severity=finding.get("severity", ""),
        exploitability_score=finding.get("exploitability_score", 0),
        file_path=finding.get("file", ""),
        line=finding.get("line", 0),
        description=finding.get("description", ""),
        evidence=finding.get("evidence", ""),
        recommendation=finding.get("recommendation", ""),
        auth_context=finding.get("auth_context", ""),
        attack_scenario=finding.get("attack_scenario", "N/A"),
        language=language,
        source_code=source_code,
    )

    messages = [
        {"role": "system", "content": FIXER_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    print(f"  [>] Generating fix for {finding.get('scan_id', '???')}: {finding.get('vulnerability', '???')}...")
    raw_response = await _call_llm(messages)
    fix = _parse_fix(raw_response)

    if fix:
        print(f"  [<] Fix generated: {fix['fix_summary']}")
    else:
        print(f"  [!] Failed to generate fix for {finding.get('scan_id', '???')}")

    return fix
