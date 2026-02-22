"""
Risk Profiler Agent - LLM Risk Assessment Engine
==================================================
Sends the full pipeline data (Scanner + Analyzer + Fixer)
to Azure OpenAI for OWASP Top 10 risk profiling.
Single LLM call with all findings for holistic analysis.

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
from prompts import RISK_PROFILER_SYSTEM_PROMPT, RISK_PROFILER_USER_PROMPT

# Foundry integration
FOUNDRY_ENDPOINT = os.getenv("FOUNDRY_ENDPOINT", "")
MODEL_DEPLOYMENT = os.getenv("MODEL_DEPLOYMENT", "gpt-4.1-mini")
FOUNDRY_AGENT_NAME = "RiskProfiler"

_foundry_openai = None


def _get_foundry_openai():
    """Get OpenAI client configured for Foundry project (cached)."""
    global _foundry_openai
    if _foundry_openai is None:
        from azure.ai.projects import AIProjectClient
        from azure.identity import DefaultAzureCredential
        project = AIProjectClient(
            endpoint=FOUNDRY_ENDPOINT,
            credential=DefaultAzureCredential(),
        )
        _foundry_openai = project.get_openai_client()
        print(f"  [Foundry] OpenAI client initialized for {FOUNDRY_AGENT_NAME}")
    return _foundry_openai


async def _call_llm(messages: list[dict]) -> str:
    """Call LLM via Foundry project or direct Azure OpenAI."""
    if FOUNDRY_ENDPOINT:
        return await _call_via_foundry(messages)
    return await _call_direct(messages)


async def _call_via_foundry(messages: list[dict]) -> str:
    """Call LLM through Foundry Responses API (enables telemetry + evaluation)."""
    user_parts = [m["content"] for m in messages if m["role"] == "user"]
    user_prompt = "\n\n".join(user_parts)

    def _sync_call():
        client = _get_foundry_openai()
        try:
            response = client.responses.create(
                model=FOUNDRY_AGENT_NAME,
                input=[{"role": "user", "content": user_prompt}],
                text={"format": {"type": "json_object"}},
            )
            print(f"  [Foundry] {FOUNDRY_AGENT_NAME} responded via Responses API")
            return response.output_text
        except Exception as e:
            print(f"  [Foundry] Responses API: {e}, using chat completions fallback")
            response = client.chat.completions.create(
                model=MODEL_DEPLOYMENT,
                messages=messages,
                temperature=0.1,
                max_tokens=16000,
                response_format={"type": "json_object"},
                user=FOUNDRY_AGENT_NAME,
            )
            return response.choices[0].message.content

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


def _parse_risk_profile(raw_response: str) -> dict | None:
    """Parse LLM response into risk profile dict."""
    try:
        parsed = json.loads(raw_response)

        if not isinstance(parsed, dict):
            print(f"  [!] Unexpected response type: {type(parsed)}")
            return None

        if "owasp_top_10" not in parsed:
            print("  [!] LLM response missing 'owasp_top_10' array")
            return None

        return parsed

    except json.JSONDecodeError as e:
        print(f"  [!] Failed to parse LLM response as JSON: {e}")
        print(f"  [!] Raw response: {raw_response[:500]}")
        return None


def _format_findings_for_prompt(findings: list[dict]) -> str:
    """Format a list of findings as text for the LLM prompt."""
    if not findings:
        return "No findings available."

    lines = []
    for i, finding in enumerate(findings, 1):
        lines.append(f"### Finding {i}: {finding.get('vulnerability', finding.get('name', 'Unknown'))}")
        for key, value in finding.items():
            if key not in ("vulnerability", "name") and value:
                lines.append(f"- **{key}**: {value}")
        lines.append("")

    return "\n".join(lines)


def _format_fixes_for_prompt(fixes: list[dict]) -> str:
    """Format fix results as text for the LLM prompt."""
    if not fixes:
        return "No fix results available."

    lines = []
    for fix in fixes:
        scan_id = fix.get("scan_id", "N/A")
        status = fix.get("status", "N/A")
        summary = fix.get("fix_summary", "N/A")
        pr = fix.get("pr_number", "")
        lines.append(f"- {scan_id}: {status} - {summary}")
        if pr:
            lines.append(f"  PR #{pr}: {fix.get('pr_url', '')}")

    return "\n".join(lines)


async def generate_risk_profile(
    scanner_findings: list[dict],
    analyzer_findings: list[dict],
    fixer_results: list[dict],
    pipeline_metadata: dict,
) -> dict | None:
    """Generate OWASP Top 10 risk profile from pipeline data.

    Args:
        scanner_findings: Raw findings from scanner output.
        analyzer_findings: Confirmed findings from analyzer output.
        fixer_results: Fix results from fixer output.
        pipeline_metadata: Timestamps, counts, repo info.

    Returns:
        Risk profile dict or None on failure.
    """
    user_prompt = RISK_PROFILER_USER_PROMPT.format(
        repository=pipeline_metadata.get("repository", "N/A"),
        scan_timestamp=pipeline_metadata.get("scan_timestamp", "N/A"),
        scanner_total=pipeline_metadata.get("scanner_total", 0),
        confirmed_count=len(analyzer_findings),
        false_positive_count=pipeline_metadata.get("false_positive_count", 0),
        fixes_generated=len(fixer_results),
        fixes_successful=sum(1 for f in fixer_results if f.get("status") == "SUCCESS"),
        scanner_findings=_format_findings_for_prompt(scanner_findings),
        analyzer_findings=_format_findings_for_prompt(analyzer_findings),
        fixer_results=_format_fixes_for_prompt(fixer_results),
    )

    messages = [
        {"role": "system", "content": RISK_PROFILER_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    print("  [>] Generating OWASP Top 10 risk profile...")
    raw_response = await _call_llm(messages)
    profile = _parse_risk_profile(raw_response)

    if profile:
        score = profile.get("overall_risk_score", "N/A")
        level = profile.get("risk_level", "N/A")
        cats_with_findings = sum(
            1 for c in profile.get("owasp_top_10", [])
            if c.get("findings_count", 0) > 0
        )
        print(f"  [<] Risk profile generated: score={score}, level={level}, categories={cats_with_findings}/10")
    else:
        print("  [!] Failed to generate risk profile")

    return profile
