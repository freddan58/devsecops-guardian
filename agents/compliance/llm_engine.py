"""
Compliance Agent - LLM Compliance Assessment Engine
=====================================================
Sends the full pipeline data (Scanner + Analyzer + Fixer)
to Azure OpenAI for PCI-DSS 4.0 compliance mapping.
Single LLM call with all findings for cross-finding analysis.

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
from prompts import COMPLIANCE_SYSTEM_PROMPT, COMPLIANCE_USER_PROMPT

# Foundry integration
FOUNDRY_ENDPOINT = os.getenv("FOUNDRY_ENDPOINT", "")
MODEL_DEPLOYMENT = os.getenv("MODEL_DEPLOYMENT", "gpt-4.1-mini")
FOUNDRY_AGENT_NAME = "ComplianceReporter"
FOUNDRY_ASSISTANT_ID = os.getenv("FOUNDRY_COMPLIANCE_ASSISTANT_ID", "asst_7IB6BWSQwQWlAfsDkrUZ0KUn")
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


def _parse_compliance(raw_response: str) -> dict | None:
    """Parse LLM response into compliance assessment dict."""
    try:
        parsed = json.loads(raw_response)

        if not isinstance(parsed, dict):
            print(f"  [!] Unexpected response type: {type(parsed)}")
            return None

        if "findings" not in parsed:
            print("  [!] LLM response missing 'findings' array")
            return None

        return parsed

    except json.JSONDecodeError as e:
        print(f"  [!] Failed to parse LLM response as JSON: {e}")
        print(f"  [!] Raw response: {raw_response[:500]}")
        return None


def _build_findings_detail(analyzer_findings: list[dict], fixer_results: list[dict]) -> str:
    """Build a text block describing each finding + its fix status for the LLM prompt."""
    # Build lookup: scan_id -> fixer result
    fix_map = {}
    for fix in fixer_results:
        fix_map[fix.get("scan_id", "")] = fix

    lines = []
    for i, finding in enumerate(analyzer_findings, 1):
        scan_id = finding.get("scan_id", f"SCAN-{str(i).zfill(3)}")
        fix = fix_map.get(scan_id, {})

        lines.append(f"### Finding {i}: {finding.get('vulnerability', 'Unknown')}")
        lines.append(f"- **Scan ID**: {scan_id}")
        lines.append(f"- **Analysis ID**: {finding.get('anlz_id', 'N/A')}")
        lines.append(f"- **CWE**: {finding.get('cwe', 'N/A')}")
        lines.append(f"- **Severity**: {finding.get('severity', 'N/A')}")
        lines.append(f"- **Exploitability Score**: {finding.get('exploitability_score', 'N/A')}/100")
        lines.append(f"- **File**: {finding.get('file', 'N/A')}:{finding.get('line', 'N/A')}")
        lines.append(f"- **Verdict**: {finding.get('verdict', 'N/A')}")
        lines.append(f"- **Description**: {finding.get('description', 'N/A')}")
        lines.append(f"- **Auth Context**: {finding.get('auth_context', 'N/A')}")
        lines.append(f"- **Attack Scenario**: {finding.get('attack_scenario', 'N/A')}")
        lines.append(f"- **Evidence**: {finding.get('evidence', 'N/A')}")

        # Fix status
        if fix:
            lines.append(f"- **Fix Status**: {fix.get('status', 'N/A')}")
            lines.append(f"- **Fix Summary**: {fix.get('fix_summary', 'N/A')}")
            lines.append(f"- **Fix Branch**: {fix.get('branch', 'N/A')}")
            if fix.get("pr_number"):
                lines.append(f"- **Draft PR**: #{fix['pr_number']} ({fix.get('pr_url', '')})")
        else:
            lines.append("- **Fix Status**: NO_FIX_ATTEMPTED")

        lines.append("")  # blank line separator

    return "\n".join(lines)


async def generate_compliance_assessment(
    analyzer_findings: list[dict],
    fixer_results: list[dict],
    pipeline_metadata: dict,
) -> dict | None:
    """Generate PCI-DSS 4.0 compliance assessment from pipeline data.

    Args:
        analyzer_findings: Confirmed findings from analyzer output.
        fixer_results: Fix results from fixer output.
        pipeline_metadata: Timestamps, counts, repo info.

    Returns:
        Compliance assessment dict or None on failure.
    """
    findings_detail = _build_findings_detail(analyzer_findings, fixer_results)

    false_positive_count = pipeline_metadata.get("false_positive_count", 0)

    user_prompt = COMPLIANCE_USER_PROMPT.format(
        repository=pipeline_metadata.get("repository", "N/A"),
        scan_timestamp=pipeline_metadata.get("scan_timestamp", "N/A"),
        scanner_total=pipeline_metadata.get("scanner_total", 0),
        confirmed_count=len(analyzer_findings),
        false_positive_count=false_positive_count,
        fixes_generated=len(fixer_results),
        fixes_successful=sum(1 for f in fixer_results if f.get("status") == "SUCCESS"),
        findings_detail=findings_detail,
    )

    messages = [
        {"role": "system", "content": COMPLIANCE_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    print("  [>] Generating PCI-DSS 4.0 compliance assessment...")
    raw_response = await _call_llm(messages)
    assessment = _parse_compliance(raw_response)

    if assessment:
        finding_count = len(assessment.get("findings", []))
        print(f"  [<] Assessment generated: {finding_count} findings mapped")
    else:
        print("  [!] Failed to generate compliance assessment")

    return assessment
