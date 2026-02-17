"""
Analyzer Agent - False Positive Eliminator
=============================================
Takes Scanner Agent findings + full source code and determines
which findings are real exploitable vulnerabilities vs false
positives using contextual LLM analysis.

Usage:
    python analyzer.py
    python analyzer.py --input ../scanner/reports/scanner-output.json
    python analyzer.py --input scan.json --output reports/analyzer-output.json
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone

from config import (
    ANALYZER_VERSION,
    GITHUB_OWNER,
    GITHUB_REPO,
    DEFAULT_SCANNER_INPUT,
    DEFAULT_ANALYZER_OUTPUT,
)
from github_client import read_multiple_files
from llm_engine import analyze_findings


def load_scanner_findings(input_path: str) -> tuple[list[dict], dict]:
    """Load scanner findings from JSON file.

    Returns:
        Tuple of (findings list, full report dict)
    """
    if not os.path.exists(input_path):
        print(f"  [!] Scanner output not found: {input_path}")
        print(f"  [!] Run the scanner first: cd ../scanner && python scanner.py --path demo-app")
        sys.exit(1)

    with open(input_path, "r") as f:
        report = json.load(f)

    findings = report.get("findings", [])
    if not findings:
        print("  [!] No findings in scanner output - nothing to analyze")
        sys.exit(0)

    return findings, report


def extract_file_paths(findings: list[dict]) -> list[str]:
    """Extract unique file paths from scanner findings + add context files.

    Always includes auth middleware and server.js for auth context analysis,
    even if no finding directly references them.
    """
    # Get unique files from findings
    finding_files = list({f["file"] for f in findings if f.get("file")})

    # Determine the app base path from the first finding
    # e.g., "demo-app/routes/accounts.js" -> "demo-app"
    base_path = ""
    if finding_files:
        parts = finding_files[0].split("/")
        if len(parts) >= 2:
            base_path = parts[0]

    # Always include auth context files for proper triage
    context_files = []
    if base_path:
        context_files = [
            f"{base_path}/middleware/auth.js",
            f"{base_path}/server.js",
        ]

    # Merge, avoiding duplicates
    all_files = finding_files + [f for f in context_files if f not in finding_files]

    return all_files


def merge_findings_with_analyses(
    scanner_findings: list[dict],
    analyses: list[dict],
) -> list[dict]:
    """Merge scanner findings with analyzer results, joined on scan_id.

    Each output finding has both the original scanner fields and the
    analyzer enrichment (verdict, score, auth_context, etc.).
    """
    # Build lookup: scan_id -> analysis
    analysis_map = {}
    for a in analyses:
        analysis_map[a.get("scan_id", "")] = a

    merged = []
    for i, finding in enumerate(scanner_findings):
        scan_id = finding.get("id", f"SCAN-{str(i+1).zfill(3)}")
        analysis = analysis_map.get(scan_id, {})

        merged_finding = {
            "anlz_id": analysis.get("anlz_id", f"ANLZ-{str(i+1).zfill(3)}"),
            "scan_id": scan_id,
            "verdict": analysis.get("verdict", "UNANALYZED"),
            "exploitability_score": analysis.get("exploitability_score", -1),
            # Original scanner fields
            "file": finding.get("file", ""),
            "line": finding.get("line", 0),
            "vulnerability": finding.get("vulnerability", ""),
            "cwe": finding.get("cwe", ""),
            "severity": finding.get("severity", ""),
            "description": finding.get("description", ""),
            "evidence": finding.get("evidence", ""),
            "recommendation": finding.get("recommendation", ""),
            # Analyzer enrichment
            "auth_context": analysis.get("auth_context", ""),
            "data_sensitivity": analysis.get("data_sensitivity", ""),
            "attack_scenario": analysis.get("attack_scenario"),
            "false_positive_reason": analysis.get("false_positive_reason"),
            "confirmed_evidence": analysis.get("confirmed_evidence"),
        }
        merged.append(merged_finding)

    return merged


def print_analyses(merged_findings: list[dict]):
    """Pretty-print analysis results to console."""
    if not merged_findings:
        print("\n  [OK] No findings to analyze!")
        return

    print(f"\n{'='*60}")
    print(f"  ANALYSIS RESULTS: {len(merged_findings)} findings analyzed")
    print(f"{'='*60}")

    # Sort: CONFIRMED first (by score desc), then FALSE_POSITIVE
    def sort_key(f):
        verdict_order = 0 if f["verdict"] == "CONFIRMED" else 1
        score = -(f.get("exploitability_score", 0))
        return (verdict_order, score)

    sorted_findings = sorted(merged_findings, key=sort_key)

    for f in sorted_findings:
        verdict = f["verdict"]
        score = f.get("exploitability_score", -1)

        if verdict == "FALSE_POSITIVE":
            icon = "[OK]"
            verdict_display = "FALSE_POSITIVE"
        elif score >= 90:
            icon = "[!!]"
            verdict_display = "CONFIRMED"
        elif score >= 70:
            icon = "[!]"
            verdict_display = "CONFIRMED"
        else:
            icon = "[~]"
            verdict_display = "CONFIRMED"

        print(f"\n  {icon} [{verdict_display}] {f['anlz_id']} ({f['scan_id']}): {f['vulnerability']}")
        print(f"       File: {f['file']}:{f['line']}")
        print(f"       Score: {score}/100 | {f.get('auth_context', 'N/A')}")

        if verdict == "CONFIRMED" and f.get("attack_scenario"):
            scenario = f["attack_scenario"][:120]
            print(f"       Attack: {scenario}")
        elif verdict == "FALSE_POSITIVE" and f.get("false_positive_reason"):
            reason = f["false_positive_reason"][:120]
            print(f"       Reason: {reason}")

    # Summary
    confirmed = sum(1 for f in merged_findings if f["verdict"] == "CONFIRMED")
    false_pos = sum(1 for f in merged_findings if f["verdict"] == "FALSE_POSITIVE")
    other = len(merged_findings) - confirmed - false_pos

    print(f"\n  Summary: {confirmed} CONFIRMED | {false_pos} FALSE_POSITIVE", end="")
    if other > 0:
        print(f" | {other} UNANALYZED", end="")
    print()


def save_report(merged_findings: list[dict], scanner_input: str, output_path: str):
    """Save analysis report to JSON file."""
    confirmed = sum(1 for f in merged_findings if f["verdict"] == "CONFIRMED")
    false_pos = sum(1 for f in merged_findings if f["verdict"] == "FALSE_POSITIVE")

    report = {
        "agent_name": "DevSecOps Guardian - Analyzer Agent",
        "version": ANALYZER_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repository": f"{GITHUB_OWNER}/{GITHUB_REPO}",
        "scanner_report": scanner_input,
        "total_findings": len(merged_findings),
        "confirmed_count": confirmed,
        "false_positive_count": false_pos,
        "findings": merged_findings,
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n  [*] Results saved to: {output_path}")


async def main():
    parser = argparse.ArgumentParser(description="DevSecOps Guardian - Analyzer Agent")
    parser.add_argument(
        "--input", type=str, default=DEFAULT_SCANNER_INPUT,
        help="Path to scanner JSON output file"
    )
    parser.add_argument(
        "--output", type=str, default=DEFAULT_ANALYZER_OUTPUT,
        help="Output JSON file path"
    )
    parser.add_argument("--ref", type=str, help="Branch or commit SHA for reading source files")

    args = parser.parse_args()

    # Resolve input path
    input_path = os.path.abspath(args.input)

    # Header
    print(f"\n{'='*60}")
    print(f"  DevSecOps Guardian - Analyzer Agent")
    print(f"  Scanner Input: {args.input}")
    print(f"  Mode: Finding Analysis (False Positive Elimination)")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}\n")

    # Phase 1: Load scanner findings
    print("[1/3] Loading scanner findings...")
    scanner_findings, scanner_report = load_scanner_findings(input_path)
    print(f"  Found {len(scanner_findings)} findings in scanner output")

    # Phase 2: Read source files from GitHub
    print(f"\n[2/3] Reading source files from GitHub...")
    file_paths = extract_file_paths(scanner_findings)
    print(f"  Requesting {len(file_paths)} files (including auth context files)")

    source_files = await read_multiple_files(file_paths, args.ref)
    print(f"  Read {len(source_files)} files successfully")

    if not source_files:
        print("  [!] No source files could be read - cannot analyze")
        sys.exit(1)

    # Phase 3: Analyze with LLM
    print(f"\n[3/3] Analyzing findings with LLM...")
    analyses = await analyze_findings(scanner_findings, source_files)

    if not analyses:
        print("  [!] LLM returned no analyses - check API connection")
        sys.exit(1)

    # Merge and output
    merged = merge_findings_with_analyses(scanner_findings, analyses)
    print_analyses(merged)
    save_report(merged, args.input, args.output)


if __name__ == "__main__":
    asyncio.run(main())
