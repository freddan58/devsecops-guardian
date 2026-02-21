"""
Analyzer Agent - LLM Analysis Engine
======================================
Sends scanner findings + source code to Azure OpenAI for
contextual vulnerability triage. Determines which findings
are real exploitable vulnerabilities vs false positives.
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
from prompts import ANALYZER_SYSTEM_PROMPT, ANALYZER_USER_PROMPT


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
