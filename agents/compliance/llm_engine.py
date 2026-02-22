"""
Compliance Agent - LLM Compliance Assessment Engine
=====================================================
Sends the full pipeline data (Scanner + Analyzer + Fixer)
to Azure OpenAI for PCI-DSS 4.0 compliance mapping.
Single LLM call with all findings for cross-finding analysis.

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
from prompts import COMPLIANCE_SYSTEM_PROMPT, COMPLIANCE_USER_PROMPT

# Foundry integration
FOUNDRY_ENDPOINT = os.getenv("FOUNDRY_ENDPOINT", "")
MODEL_DEPLOYMENT = os.getenv("MODEL_DEPLOYMENT", "gpt-4.1-mini")
FOUNDRY_AGENT_NAME = "ComplianceReporter"

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
