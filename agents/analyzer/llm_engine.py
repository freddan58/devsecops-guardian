"""
Analyzer Agent - LLM Analysis Engine
======================================
Sends scanner findings + source code to Azure OpenAI for
contextual vulnerability triage. Determines which findings
are real exploitable vulnerabilities vs false positives.

Supports two modes:
- Foundry mode (FOUNDRY_ENDPOINT set): Routes calls through Azure AI Foundry
  Responses API. The Foundry "prompt" agents (VulnerabilityAnalyzer:2 etc.) apply
  guardrails (DevSecOps-Guardian-Safety) and evaluations automatically.
  ResponsesInstrumentor captures gen_ai.* spans for App Insights / Operate tab.
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
from prompts import ANALYZER_SYSTEM_PROMPT, ANALYZER_USER_PROMPT

# Foundry integration
FOUNDRY_ENDPOINT = os.getenv("FOUNDRY_ENDPOINT", "")
MODEL_DEPLOYMENT = os.getenv("MODEL_DEPLOYMENT", "gpt-4.1-mini")
FOUNDRY_AGENT_NAME = "VulnerabilityAnalyzer"

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
    """Call LLM via Foundry Responses API or direct Azure OpenAI."""
    if FOUNDRY_ENDPOINT:
        try:
            return await _call_via_foundry(messages)
        except Exception as e:
            print(f"  [!] Foundry call failed ({e}), falling back to direct Azure OpenAI")
    return await _call_direct(messages)


async def _call_via_foundry(messages: list[dict]) -> str:
    """Call LLM through Foundry Responses API with telemetry + guardrails.

    Uses model=MODEL_DEPLOYMENT with instructions=system_prompt so that:
    - The call routes through the Foundry endpoint (guardrails applied)
    - ResponsesInstrumentor generates gen_ai.* spans for App Insights / Operate tab
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


def _parse_analyses(raw_response: str) -> list[dict]:
    """Parse LLM response into structured analyses list. Never crashes."""
    try:
        parsed = json.loads(raw_response)

        if isinstance(parsed, dict):
            print(f"  [DEBUG] Response keys: {list(parsed.keys())}")

        # Handle various key names defensively
        if isinstance(parsed, dict):
            if "analyses" in parsed:
                parsed = parsed["analyses"]
            elif "findings" in parsed:
                parsed = parsed["findings"]
            elif "results" in parsed:
                parsed = parsed["results"]
            else:
                for key, value in parsed.items():
                    if isinstance(value, list):
                        print(f"  [DEBUG] Using key '{key}' as analyses array")
                        parsed = value
                        break
                else:
                    return []

        if not isinstance(parsed, list):
            print(f"  [!] Unexpected response type: {type(parsed)}")
            return []

        validated = []
        for i, analysis in enumerate(parsed):
            if not isinstance(analysis, dict):
                continue

            # Normalize field names defensively
            if "finding_id" in analysis and "scan_id" not in analysis:
                analysis["scan_id"] = analysis["finding_id"]
            if "id" in analysis and "scan_id" not in analysis:
                analysis["scan_id"] = analysis["id"]
            if "status" in analysis and "verdict" not in analysis:
                analysis["verdict"] = analysis["status"]
            if "score" in analysis and "exploitability_score" not in analysis:
                analysis["exploitability_score"] = analysis["score"]

            # Required minimum fields
            required = {"scan_id", "verdict"}
            missing = required - analysis.keys()
            if missing:
                print(f"  [!] Analysis {i} missing fields: {missing}")
                continue

            # Normalize verdict to uppercase
            analysis["verdict"] = str(analysis.get("verdict", "")).upper()
            if analysis["verdict"] not in ("CONFIRMED", "FALSE_POSITIVE"):
                raw_verdict = analysis["verdict"].lower()
                if "false" in raw_verdict or "fp" in raw_verdict:
                    analysis["verdict"] = "FALSE_POSITIVE"
                else:
                    analysis["verdict"] = "CONFIRMED"

            # Ensure exploitability_score exists
            if "exploitability_score" not in analysis:
                analysis["exploitability_score"] = (
                    0 if analysis["verdict"] == "FALSE_POSITIVE" else 50
                )

            # Preserve new enrichment fields (pass through as-is)
            # analysis_reasoning and best_practices_analysis are already in the dict
            # Just ensure defaults if missing
            if "analysis_reasoning" not in analysis:
                analysis["analysis_reasoning"] = ""
            if "best_practices_analysis" not in analysis:
                analysis["best_practices_analysis"] = {
                    "violated_practices": [],
                    "followed_practices": [],
                }

            validated.append(analysis)

        return validated

    except json.JSONDecodeError as e:
        print(f"  [!] Failed to parse LLM response as JSON: {e}")
        print(f"  [!] Raw response: {raw_response[:500]}")
        return []


async def analyze_findings(
    scanner_findings: list[dict],
    source_files: list[dict],
) -> list[dict]:
    """Send all scanner findings + source files to LLM for contextual analysis.

    Args:
        scanner_findings: List of finding dicts from scanner-output.json
        source_files: List of {path, content} dicts read from GitHub

    Returns:
        List of analysis dicts with verdict, score, and context
    """
    # Build source files content block
    files_parts = []
    for f in source_files:
        language = _get_language(f["path"])
        files_parts.append(
            f"**File**: `{f['path']}`\n```{language}\n{f['content']}\n```"
        )
    source_files_content = "\n\n---\n\n".join(files_parts)

    user_prompt = ANALYZER_USER_PROMPT.format(
        scanner_findings_json=json.dumps(scanner_findings, indent=2),
        source_files_content=source_files_content,
        finding_count=len(scanner_findings),
    )

    messages = [
        {"role": "system", "content": ANALYZER_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    print(f"  [>] Sending {len(scanner_findings)} findings + {len(source_files)} source files to LLM...")
    raw_response = await _call_llm(messages)
    analyses = _parse_analyses(raw_response)
    print(f"  [<] Received {len(analyses)} analyses")

    return analyses
