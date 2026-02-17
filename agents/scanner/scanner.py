"""
DevSecOps Guardian - Scanner Agent
====================================
AI-native code security scanner that uses LLM reasoning to detect
vulnerabilities in banking applications. Replaces traditional SAST
tools (SonarQube, Checkmarx) with contextual understanding.

Usage:
    # Scan full repo directory
    python scanner.py --path demo-app

    # Scan a specific PR
    python scanner.py --pr 1

    # Scan specific files
    python scanner.py --files demo-app/routes/accounts.js demo-app/routes/users.js
"""

import asyncio
import argparse
import json
import os
import sys
from datetime import datetime, timezone

from config import GITHUB_OWNER, GITHUB_REPO
from github_client import list_repo_files, read_file_content, read_multiple_files, get_pr_changed_files
from llm_engine import scan_single_file, scan_multiple_files
from smart_scan import smart_scan, build_context_map, scan_group_with_context


async def scan_directory(path: str, ref: str = None) -> list[dict]:
    """Scan all files in a repo directory.
    
    Discovers files, reads content, sends to LLM in batches.
    """
    print(f"\n{'='*60}")
    print(f"  DevSecOps Guardian - Scanner Agent")
    print(f"  Target: {GITHUB_OWNER}/{GITHUB_REPO}/{path}")
    print(f"  Mode: Full Directory Scan")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}\n")

    # Step 1: Discover files
    print("[1/3] Discovering files...")
    files = await list_repo_files(path, ref)
    print(f"  Found {len(files)} scannable files\n")

    if not files:
        print("  No scannable files found.")
        return []

    for f in files:
        print(f"    {f['path']}")

    # Step 2: Read file contents
    print(f"\n[2/3] Reading file contents...")
    file_paths = [f["path"] for f in files]
    file_data = await read_multiple_files(file_paths, ref)
    print(f"  Read {len(file_data)} files successfully\n")

    # Step 3: Smart Scan with LLM (context map -> grouped scan -> deduplicate)
    print(f"[3/3] Smart scanning with LLM...")
    findings = await smart_scan(file_data)

    return findings


async def scan_pr(pr_number: int) -> list[dict]:
    """Scan files changed in a Pull Request."""
    print(f"\n{'='*60}")
    print(f"  DevSecOps Guardian - Scanner Agent")
    print(f"  Target: {GITHUB_OWNER}/{GITHUB_REPO} PR #{pr_number}")
    print(f"  Mode: Pull Request Scan")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}\n")

    # Step 1: Get changed files
    print("[1/3] Getting PR changed files...")
    changed = await get_pr_changed_files(pr_number)
    print(f"  Found {len(changed)} scannable changed files\n")

    if not changed:
        print("  No scannable files in this PR.")
        return []

    for f in changed:
        print(f"    [{f['status']}] {f['filename']}")

    # Step 2: Read full file contents (not just patches)
    print(f"\n[2/3] Reading full file contents...")
    file_paths = [f["filename"] for f in changed]
    file_data = await read_multiple_files(file_paths)
    print(f"  Read {len(file_data)} files successfully\n")

    # Step 3: Scan
    print(f"[3/3] Scanning with LLM...")
    findings = await scan_multiple_files(file_data)

    for i, f in enumerate(findings):
        f["id"] = f"SCAN-{str(i + 1).zfill(3)}"
        f["pr_number"] = pr_number

    return findings


async def scan_files(file_paths: list[str], ref: str = None) -> list[dict]:
    """Scan specific files."""
    print(f"\n{'='*60}")
    print(f"  DevSecOps Guardian - Scanner Agent")
    print(f"  Target: {len(file_paths)} specific files")
    print(f"  Mode: File List Scan")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}\n")

    print("[1/2] Reading files...")
    file_data = await read_multiple_files(file_paths, ref)
    print(f"  Read {len(file_data)} files\n")

    print("[2/2] Scanning with LLM...")
    findings = await scan_multiple_files(file_data)

    for i, f in enumerate(findings):
        f["id"] = f"SCAN-{str(i + 1).zfill(3)}"

    return findings


def print_findings(findings: list[dict]):
    """Pretty-print findings to console."""
    if not findings:
        print("\n  [OK] No vulnerabilities detected!")
        return

    print(f"\n{'='*60}")
    print(f"  SCAN RESULTS: {len(findings)} findings")
    print(f"{'='*60}")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "LOW"), 9))

    severity_icons = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[.]"}

    for f in sorted_findings:
        icon = severity_icons.get(f.get("severity", ""), "[ ]")
        print(f"\n  {icon} [{f.get('severity', '?')}] {f.get('id', '?')}: {f.get('vulnerability', '?')}")
        print(f"     File: {f.get('file', '?')}:{f.get('line', '?')}")
        print(f"     CWE: {f.get('cwe', 'N/A')}")
        print(f"     {f.get('description', '')}")
        if f.get("evidence"):
            evidence = f["evidence"][:120] + "..." if len(f.get("evidence", "")) > 120 else f.get("evidence", "")
            print(f"     Evidence: {evidence}")

    # Summary
    counts = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1

    print(f"\n  Summary: ", end="")
    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in counts:
            parts.append(f"{counts[sev]} {sev}")
    print(" | ".join(parts))


def save_findings(findings: list[dict], output_path: str):
    """Save findings to JSON file."""
    report = {
        "scanner": "DevSecOps Guardian - Scanner Agent",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repository": f"{GITHUB_OWNER}/{GITHUB_REPO}",
        "total_findings": len(findings),
        "findings": findings,
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n  [*] Results saved to: {output_path}")


async def main():
    parser = argparse.ArgumentParser(description="DevSecOps Guardian - Scanner Agent")
    parser.add_argument("--path", type=str, help="Repo directory to scan (e.g., 'demo-app')")
    parser.add_argument("--pr", type=int, help="PR number to scan")
    parser.add_argument("--files", nargs="+", help="Specific file paths to scan")
    parser.add_argument("--ref", type=str, help="Branch or commit SHA")
    parser.add_argument("--output", type=str, default="reports/scanner-output.json", help="Output JSON file path")

    args = parser.parse_args()

    # Validate we have at least one scan target
    if not any([args.path, args.pr, args.files]):
        parser.print_help()
        print("\n  Error: Provide --path, --pr, or --files")
        sys.exit(1)

    # Run the appropriate scan
    if args.pr:
        findings = await scan_pr(args.pr)
    elif args.files:
        findings = await scan_files(args.files, args.ref)
    else:
        findings = await scan_directory(args.path, args.ref)

    # Display and save
    print_findings(findings)
    save_findings(findings, args.output)

    return findings


if __name__ == "__main__":
    asyncio.run(main())
