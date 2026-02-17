"""
Scanner Agent - LLM Security Analysis Engine
==============================================
Sends source code to Azure OpenAI (GPT-4o-mini) for security analysis.
The LLM acts as a senior AppSec engineer, detecting vulnerabilities
that traditional SAST tools miss (business logic flaws, context-aware
analysis).
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
from prompts import SCANNER_SYSTEM_PROMPT, SCAN_FILE_PROMPT, SCAN_MULTIPLE_FILES_PROMPT


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
        "temperature": 0.1,  # Low temperature for consistent, precise analysis
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


def _parse_findings(raw_response: str) -> list[dict]:
    """Parse LLM response into structured findings list."""
    try:
        parsed = json.loads(raw_response)

        # Debug: show what the LLM returned
        if isinstance(parsed, dict):
            print(f"  [DEBUG] Response keys: {list(parsed.keys())}")

        # Handle {"findings": [...]} or any key containing a list
        if isinstance(parsed, dict):
            if "findings" in parsed:
                parsed = parsed["findings"]
            elif "vulnerabilities" in parsed:
                parsed = parsed["vulnerabilities"]
            elif "results" in parsed:
                parsed = parsed["results"]
            else:
                # Find first key that has a list value
                for key, value in parsed.items():
                    if isinstance(value, list):
                        print(f"  [DEBUG] Using key '{key}' as findings array")
                        parsed = value
                        break
                else:
                    # Single finding wrapped in object - check if it has vuln fields
                    if "vulnerability" in parsed or "cwe" in parsed:
                        parsed = [parsed]
                    else:
                        print(f"  [DEBUG] Unexpected object structure: {json.dumps(parsed)[:500]}")
                        return []

        if not isinstance(parsed, list):
            print(f"  [!] Unexpected response type: {type(parsed)}")
            return []

        # Validate and normalize each finding
        validated = []
        for i, finding in enumerate(parsed):
            if not isinstance(finding, dict):
                continue

            # Normalize field names (LLMs sometimes use variants)
            if "filename" in finding and "file" not in finding:
                finding["file"] = finding["filename"]
            if "file_path" in finding and "file" not in finding:
                finding["file"] = finding["file_path"]
            if "type" in finding and "vulnerability" not in finding:
                finding["vulnerability"] = finding["type"]
            if "title" in finding and "vulnerability" not in finding:
                finding["vulnerability"] = finding["title"]
            if "name" in finding and "vulnerability" not in finding:
                finding["vulnerability"] = finding["name"]
            if "risk" in finding and "severity" not in finding:
                finding["severity"] = finding["risk"]
            if "level" in finding and "severity" not in finding:
                finding["severity"] = finding["level"]
            if "line_number" in finding and "line" not in finding:
                finding["line"] = finding["line_number"]

            # Check minimum required fields
            required_fields = {"file", "vulnerability", "severity"}
            missing = required_fields - finding.keys()
            if missing:
                print(f"  [!] Finding {i} missing fields: {missing} - keys: {list(finding.keys())}")
                continue

            # Ensure ID exists
            if "id" not in finding:
                finding["id"] = f"SCAN-{str(i + 1).zfill(3)}"
            validated.append(finding)

        return validated

    except json.JSONDecodeError as e:
        print(f"  [!] Failed to parse LLM response as JSON: {e}")
        print(f"  [!] Raw response: {raw_response[:500]}")
        return []


async def scan_single_file(file_path: str, code: str) -> list[dict]:
    """Scan a single file for security vulnerabilities using LLM.
    
    Args:
        file_path: Path to the file in the repo
        code: File content
    
    Returns:
        List of findings dicts
    """
    language = _get_language(file_path)

    user_prompt = SCAN_FILE_PROMPT.format(
        file_path=file_path,
        language=language,
        code=code,
    )

    messages = [
        {"role": "system", "content": SCANNER_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    print(f"  [>] Scanning {file_path} ...")
    raw_response = await _call_llm(messages)
    findings = _parse_findings(raw_response)
    print(f"  [<] {file_path}: {len(findings)} findings")

    # Ensure file path is set correctly on each finding
    for f in findings:
        if not f.get("file") or f["file"] == "path/to/file.js":
            f["file"] = file_path

    return findings


async def scan_multiple_files(files: list[dict]) -> list[dict]:
    """Scan multiple files together for cross-file context analysis.
    
    Args:
        files: List of {path, content} dicts
        
    Returns:
        List of findings dicts across all files
    """
    # Build combined content block
    files_content_parts = []
    for f in files:
        language = _get_language(f["path"])
        files_content_parts.append(
            f"**File**: `{f['path']}`\n```{language}\n{f['content']}\n```"
        )

    files_content = "\n\n---\n\n".join(files_content_parts)

    user_prompt = SCAN_MULTIPLE_FILES_PROMPT.format(files_content=files_content)

    messages = [
        {"role": "system", "content": SCANNER_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    print(f"  [>] Scanning {len(files)} files together ...")
    raw_response = await _call_llm(messages)
    findings = _parse_findings(raw_response)
    print(f"  [<] Batch scan: {len(findings)} total findings")

    return findings
