"""
Fixer Agent - LLM Fix Generation Engine
=========================================
Sends confirmed vulnerability details + source code to Azure
OpenAI to generate production-ready security fixes.
One LLM call per finding (each fix needs focused attention).

Supports three modes (tried in order):
1. Foundry Threads/Runs (FOUNDRY_ENDPOINT set): Creates agent threads visible
   in Foundry Operate tab with full run tracking and telemetry.
2. Foundry Responses API (fallback): Routes calls through Azure AI Foundry
   for telemetry via ResponsesInstrumentor.
3. Direct mode (fallback): Uses httpx to call Azure OpenAI directly.
"""

import asyncio
import json
import os
import time
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
FOUNDRY_ASSISTANT_ID = os.getenv("FOUNDRY_FIXER_ASSISTANT_ID", "asst_C21MlxwOg7RrYXOpxmfwOJt5")
FOUNDRY_API_VERSION = os.getenv("FOUNDRY_API_VERSION", "2025-05-01")

_foundry_client = None
_foundry_openai = None
_tracing_initialized = False


def _init_tracing():
    """Initialize OpenTelemetry tracing + ResponsesInstrumentor for Foundry telemetry."""
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


def _get_foundry_client():
    """Get AIProjectClient for Foundry thread/run REST calls (cached)."""
    global _foundry_client
    if _foundry_client is None:
        _init_tracing()
        from azure.ai.projects import AIProjectClient
        from azure.identity import DefaultAzureCredential
        _foundry_client = AIProjectClient(
            endpoint=FOUNDRY_ENDPOINT,
            credential=DefaultAzureCredential(),
        )
        print(f"  [Foundry] AIProjectClient initialized for {FOUNDRY_AGENT_NAME}")
    return _foundry_client


def _get_foundry_openai():
    """Get OpenAI client configured for Foundry project (cached)."""
    global _foundry_openai
    if _foundry_openai is None:
        client = _get_foundry_client()
        _foundry_openai = client.get_openai_client()
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
    """Call LLM via Foundry threads/runs, Responses API, or direct Azure OpenAI."""
    if FOUNDRY_ENDPOINT:
        try:
            return await _call_via_foundry_threads(messages)
        except Exception as e:
            print(f"  [!] Foundry threads/runs failed ({e}), trying Responses API...")
        try:
            return await _call_via_foundry(messages)
        except Exception as e:
            print(f"  [!] Foundry Responses API failed ({e}), falling back to direct Azure OpenAI")
    return await _call_direct(messages)


def _foundry_api(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    """Make a REST call to the Foundry API via AIProjectClient.send_request()."""
    from azure.core.rest import HttpRequest
    client = _get_foundry_client()
    url = f"{FOUNDRY_ENDPOINT}{path}?api-version={FOUNDRY_API_VERSION}"
    kw = {"method": method, "url": url, "headers": {"Content-Type": "application/json"}}
    if body is not None:
        kw["json"] = body
    req = HttpRequest(**kw)
    resp = client.send_request(req)
    return resp.status_code, json.loads(resp.text())


async def _call_via_foundry_threads(messages: list[dict]) -> str:
    """Call agent via Foundry threads/runs API (creates tracked runs in Operate tab)."""
    system_parts = [m["content"] for m in messages if m["role"] == "system"]
    user_parts = [m["content"] for m in messages if m["role"] == "user"]
    system_prompt = "\n\n".join(system_parts) if system_parts else None
    user_prompt = "\n\n".join(user_parts)

    def _sync_call():
        thread_id = None
        try:
            status, thread = _foundry_api("POST", "/threads")
            if status != 200:
                raise RuntimeError(f"Thread create failed ({status}): {thread}")
            thread_id = thread["id"]

            status, msg = _foundry_api("POST", f"/threads/{thread_id}/messages", {
                "role": "user", "content": user_prompt,
            })
            if status != 200:
                raise RuntimeError(f"Message create failed ({status}): {msg}")

            run_body = {"assistant_id": FOUNDRY_ASSISTANT_ID}
            if system_prompt:
                run_body["additional_instructions"] = system_prompt
            status, run = _foundry_api("POST", f"/threads/{thread_id}/runs", run_body)
            if status != 200:
                raise RuntimeError(f"Run create failed ({status}): {run}")

            run_id = run["id"]
            print(f"  [Foundry] {FOUNDRY_AGENT_NAME} run started: {run_id} (thread={thread_id})")

            for i in range(90):
                time.sleep(2)
                status, run_check = _foundry_api("GET", f"/threads/{thread_id}/runs/{run_id}")
                run_status = run_check.get("status", "unknown")
                if run_status == "completed":
                    break
                elif run_status in ("failed", "cancelled", "expired"):
                    raise RuntimeError(f"Run {run_status}: {run_check.get('last_error', {})}")
            else:
                raise RuntimeError("Run timed out after 3 minutes")

            status, msgs = _foundry_api("GET", f"/threads/{thread_id}/messages")
            if status != 200:
                raise RuntimeError(f"Messages read failed ({status})")

            for m in msgs.get("data", []):
                if m.get("role") == "assistant":
                    for c in m.get("content", []):
                        if c.get("type") == "text":
                            text = c["text"]["value"]
                            print(f"  [Foundry] {FOUNDRY_AGENT_NAME} responded via threads/runs (run={run_id})")
                            return text

            raise RuntimeError("No assistant response found in thread messages")
        finally:
            if thread_id:
                try:
                    _foundry_api("DELETE", f"/threads/{thread_id}")
                except Exception:
                    pass

    return await asyncio.to_thread(_sync_call)


async def _call_via_foundry(messages: list[dict]) -> str:
    """Call LLM through Foundry Responses API (fallback with telemetry)."""
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
