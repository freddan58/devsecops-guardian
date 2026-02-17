"""
Fixer Agent - LLM Fix Generation Engine
=========================================
Sends confirmed vulnerability details + source code to Azure
OpenAI to generate production-ready security fixes.
One LLM call per finding (each fix needs focused attention).
"""

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
    """Call Azure OpenAI chat completion API."""
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
        "max_tokens": 8000,
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
