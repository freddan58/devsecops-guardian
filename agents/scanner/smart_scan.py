"""
Scanner Agent - Smart Scan Strategy for Large Repos
=====================================================
Instead of sending all files at once (which doesn't scale),
we use a 3-phase approach:

Phase 1 - CONTEXT MAP: Build a lightweight summary of the repo
  - File tree, imports/exports, middleware chain, route map
  - This is ~500 tokens vs ~50K tokens for full code

Phase 2 - GROUPED SCAN: Scan files in logical groups
  - Each group gets the context map + full code of its files
  - Groups: config, middleware, routes, utils, etc.

Phase 3 - CONSOLIDATE: Merge and deduplicate findings

This allows scanning repos with 100+ files while maintaining
cross-file context awareness.
"""

import json
import os
from typing import Optional

from github_client import list_repo_files, read_multiple_files
from llm_engine import _call_llm, _parse_findings
from prompts import SCANNER_SYSTEM_PROMPT


# ============================================================
# Phase 1: Build Context Map
# ============================================================

CONTEXT_MAP_PROMPT = """Analyze these source code files and produce a concise CONTEXT MAP for security analysis.

The context map should capture:
1. **Auth pattern**: How authentication works (JWT, session, API key), which middleware enforces it
2. **Route protection**: Which routes/endpoints have auth middleware applied and which are PUBLIC (no auth)
3. **Data flow**: Where user input enters (query params, body, headers) and where it's used (SQL, HTML, logs, files)
4. **Sensitive operations**: Database queries, file operations, crypto, external API calls
5. **Middleware chain**: What middleware runs on each route group

Respond ONLY with a JSON object:

```json
{{
  "context_map": {{
    "auth_mechanism": "Brief description of auth (e.g., JWT via middleware/auth.js, bcrypt for passwords)",
    "public_endpoints": ["GET /api/accounts", "GET /api/search", "DELETE /api/users/:id"],
    "protected_endpoints": ["GET /api/balance", "GET /api/transfers", "POST /api/transfers"],
    "middleware_chain": ["requestLogger (all routes)", "authenticateToken (selected routes)"],
    "database": "SQLite via better-sqlite3",
    "input_sources": ["req.query (accounts, search)", "req.body (transfers, users)", "req.params (all)"],
    "sensitive_data": ["account numbers", "balances", "SSN in logs", "API keys in config"],
    "crypto_usage": "bcrypt for password hashing (salt rounds: 10)",
    "file_summary": {{
      "config/database.js": "DB connection config with hardcoded credentials",
      "middleware/auth.js": "JWT authentication middleware",
      "routes/accounts.js": "Account lookup - PUBLIC, uses raw SQL"
    }}
  }}
}}
```

Here are the source files:

{files_content}
"""

GROUPED_SCAN_PROMPT = """You are scanning a banking application for security vulnerabilities.

## REPO CONTEXT MAP (summary of full application - DO NOT scan this, use it for context only):
```json
{context_map}
```

## FILES TO SCAN (analyze these files for vulnerabilities):

{files_content}

## RULES
- Use the context map to understand which endpoints are public vs protected
- A SQL query behind JWT auth + parameterized query is LOWER risk than one on a public endpoint
- Hardcoded secrets are always a finding regardless of auth
- PII in logs is a finding regardless of auth
- Report ALL vulnerabilities you find in the files above
- Do NOT report issues in files not shown above (they'll be scanned separately)

Respond ONLY with a JSON object containing a "findings" array:
```json
{{
  "findings": [
    {{
      "id": "SCAN-001",
      "file": "path/to/file.js",
      "line": 25,
      "vulnerability": "SQL Injection",
      "cwe": "CWE-89",
      "severity": "CRITICAL",
      "description": "Detailed description of the vulnerability",
      "evidence": "The actual vulnerable code snippet",
      "recommendation": "How to fix it"
    }}
  ]
}}
```

If no vulnerabilities found in these files, respond with: {{"findings": []}}
"""


def _get_language(file_path: str) -> str:
    """Infer language from file extension."""
    ext_map = {
        ".js": "javascript", ".ts": "typescript", ".jsx": "javascript",
        ".tsx": "typescript", ".py": "python", ".java": "java",
        ".cs": "csharp", ".go": "go", ".rb": "ruby", ".php": "php",
        ".yml": "yaml", ".yaml": "yaml", ".json": "json",
    }
    _, ext = os.path.splitext(file_path)
    return ext_map.get(ext.lower(), "text")


def _build_files_content(file_data: list[dict]) -> str:
    """Format files for LLM prompt."""
    parts = []
    for f in file_data:
        language = _get_language(f["path"])
        parts.append(f"**File**: `{f['path']}`\n```{language}\n{f['content']}\n```")
    return "\n\n---\n\n".join(parts)


def _group_files(file_data: list[dict]) -> list[list[dict]]:
    """Group files by directory/purpose for scanning.
    
    Strategy: Group by parent directory, keeping related files together.
    Each group is small enough for one LLM call (~8 files max).
    """
    groups = {}
    for f in file_data:
        # Use parent directory as group key
        parts = f["path"].split("/")
        if len(parts) >= 3:
            # e.g., demo-app/routes/accounts.js -> "routes"
            group_key = parts[-2]
        elif len(parts) == 2:
            group_key = "root"
        else:
            group_key = "root"
        
        if group_key not in groups:
            groups[group_key] = []
        groups[group_key].append(f)
    
    # Merge small groups (< 2 files) into nearest group
    result = []
    small_files = []
    for key, files in groups.items():
        if len(files) < 2:
            small_files.extend(files)
        else:
            result.append(files)
    
    # Add small files to first group or make their own
    if small_files:
        if result:
            result[0].extend(small_files)
        else:
            result.append(small_files)
    
    # Split any group larger than 8 files
    final_groups = []
    for group in result:
        if len(group) <= 8:
            final_groups.append(group)
        else:
            for i in range(0, len(group), 8):
                final_groups.append(group[i:i+8])
    
    return final_groups


async def build_context_map(file_data: list[dict]) -> dict:
    """Phase 1: Build a lightweight context map of the entire repo.
    
    Sends all files to the LLM but asks for a SUMMARY, not findings.
    This produces a ~500 token context map that can be included
    in every subsequent scan call.
    """
    print("  [Phase 1] Building context map...")
    
    files_content = _build_files_content(file_data)
    prompt = CONTEXT_MAP_PROMPT.format(files_content=files_content)
    
    messages = [
        {"role": "system", "content": "You are a security architecture analyst. Produce concise context maps for security scanning."},
        {"role": "user", "content": prompt},
    ]
    
    raw_response = await _call_llm(messages)
    
    try:
        parsed = json.loads(raw_response)
        context_map = parsed.get("context_map", parsed)
        print(f"  [Phase 1] Context map built: {len(json.dumps(context_map))} chars")
        print(f"    - Public endpoints: {len(context_map.get('public_endpoints', []))}")
        print(f"    - Protected endpoints: {len(context_map.get('protected_endpoints', []))}")
        return context_map
    except json.JSONDecodeError:
        print("  [!] Failed to parse context map, using empty context")
        return {}


async def scan_group_with_context(
    group_files: list[dict],
    context_map: dict,
    group_label: str = "",
) -> list[dict]:
    """Phase 2: Scan a group of files with the context map.
    
    Each group gets:
    - The full context map (lightweight, ~500 tokens)
    - Full source code of files in this group only
    """
    files_content = _build_files_content(group_files)
    context_json = json.dumps(context_map, indent=2)
    
    prompt = GROUPED_SCAN_PROMPT.format(
        context_map=context_json,
        files_content=files_content,
    )
    
    messages = [
        {"role": "system", "content": SCANNER_SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    
    file_names = [f["path"].split("/")[-1] for f in group_files]
    label = group_label or ", ".join(file_names)
    print(f"  [Phase 2] Scanning group: {label} ({len(group_files)} files)")
    
    raw_response = await _call_llm(messages)
    findings = _parse_findings(raw_response)
    print(f"  [Phase 2] Group result: {len(findings)} findings")
    
    return findings


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Phase 3: Remove duplicate findings from different scan groups.
    
    Dedup key: (file, line, cwe). Keep the one with longer description.
    """
    seen = {}
    for f in findings:
        key = (f.get("file", ""), f.get("line", 0), f.get("cwe", ""))
        if key not in seen:
            seen[key] = f
        else:
            # Keep the finding with more detail
            existing_desc_len = len(seen[key].get("description", ""))
            new_desc_len = len(f.get("description", ""))
            if new_desc_len > existing_desc_len:
                seen[key] = f
    
    # Re-assign sequential IDs
    result = list(seen.values())
    for i, f in enumerate(result):
        f["id"] = f"SCAN-{str(i + 1).zfill(3)}"
    
    return result


async def smart_scan(file_data: list[dict]) -> list[dict]:
    """Full smart scan pipeline: context map → grouped scan → deduplicate.
    
    For small repos (≤ 15 files): still does context map + single group
    For large repos: context map + multiple groups + dedup
    """
    total_files = len(file_data)
    
    # Phase 1: Build context map (always, even for small repos)
    context_map = await build_context_map(file_data)
    
    # Phase 2: Scan in groups
    if total_files <= 15:
        # Small repo: one group with context
        all_findings = await scan_group_with_context(
            file_data, context_map, "all files"
        )
    else:
        # Large repo: group by directory and scan each
        groups = _group_files(file_data)
        print(f"  [Phase 2] Split into {len(groups)} scan groups")
        
        all_findings = []
        for i, group in enumerate(groups):
            group_label = f"Group {i+1}/{len(groups)}"
            findings = await scan_group_with_context(group, context_map, group_label)
            all_findings.extend(findings)
    
    # Phase 3: Deduplicate
    print(f"\n  [Phase 3] Deduplicating {len(all_findings)} raw findings...")
    final_findings = deduplicate_findings(all_findings)
    print(f"  [Phase 3] Final: {len(final_findings)} unique findings")
    
    return final_findings
