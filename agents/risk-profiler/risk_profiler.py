"""
Risk Profiler Agent - OWASP Top 10 Risk Assessment
=====================================================
Takes the complete pipeline output (Scanner + Analyzer + Fixer)
and generates an OWASP Top 10 risk profile with attack surface analysis.

Pipeline inputs:
  - Scanner output: raw findings
  - Analyzer output: confirmed findings with triage
  - Fixer output: fix status (optional)

Output:
  - risk-profile-output.json: Structured risk profile data

Usage:
    python risk_profiler.py
    python risk_profiler.py --scanner ../scanner/reports/scanner-output.json
    python risk_profiler.py --analyzer ../analyzer/reports/analyzer-output.json
    python risk_profiler.py --fixer ../fixer/reports/fixer-output.json
    python risk_profiler.py --output reports/risk-profile-output.json
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone

from config import (
    RISK_PROFILER_VERSION,
    GITHUB_OWNER,
    GITHUB_REPO,
    DEFAULT_SCANNER_INPUT,
    DEFAULT_ANALYZER_INPUT,
    DEFAULT_FIXER_INPUT,
    DEFAULT_RISK_OUTPUT,
)
from llm_engine import generate_risk_profile


def load_json_report(path: str, agent_name: str) -> dict:
    """Load a JSON report file, with helpful error messages."""
    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        print(f"  [!] {agent_name} output not found: {abs_path}")
        print(f"  [!] Run the {agent_name.lower()} first")
        return {}

    with open(abs_path, "r") as f:
        return json.load(f)


def load_pipeline_data(
    scanner_path: str, analyzer_path: str, fixer_path: str
) -> tuple:
    """Load all upstream agent outputs.

    Returns:
        (scanner_findings, analyzer_findings, fixer_results, pipeline_metadata)
    """
    # Scanner report (has raw findings)
    scanner_report = load_json_report(scanner_path, "Scanner")

    # Analyzer report (required - has confirmed findings)
    analyzer_report = load_json_report(analyzer_path, "Analyzer")
    if not analyzer_report:
        print("  [!] Analyzer output is required for risk profiling")
        sys.exit(1)

    # Fixer report (optional - enriches with fix status)
    fixer_report = load_json_report(fixer_path, "Fixer")

    # Extract scanner raw findings
    scanner_findings = scanner_report.get("findings", [])

    # Extract confirmed findings from analyzer
    all_findings = analyzer_report.get("findings", [])
    confirmed_findings = [f for f in all_findings if f.get("verdict") == "CONFIRMED"]

    if not confirmed_findings:
        print("  [OK] No confirmed findings - generating minimal risk profile")

    # Extract fixer results
    fixer_results = fixer_report.get("fixes", [])

    # Build metadata from all sources
    pipeline_metadata = {
        "repository": f"{GITHUB_OWNER}/{GITHUB_REPO}",
        "scan_timestamp": scanner_report.get(
            "timestamp", analyzer_report.get("timestamp", "")
        ),
        "scanner_total": scanner_report.get("total_findings", len(all_findings)),
        "false_positive_count": analyzer_report.get("false_positive_count", 0),
    }

    return scanner_findings, confirmed_findings, fixer_results, pipeline_metadata


def print_risk_profile(profile: dict):
    """Pretty-print risk profile to console."""
    score = profile.get("overall_risk_score", 0)
    level = profile.get("risk_level", "N/A")

    print(f"\n{'='*60}")
    print(f"  OWASP TOP 10 RISK PROFILE")
    print(f"  Overall Score: {score}/100 ({level})")
    print(f"{'='*60}")

    for cat in profile.get("owasp_top_10", []):
        category = cat.get("category", "Unknown")
        cat_score = cat.get("score", 0)
        count = cat.get("findings_count", 0)

        if cat_score >= 80:
            icon = "[!!]"
        elif cat_score >= 60:
            icon = "[!]"
        elif cat_score >= 40:
            icon = "[~]"
        elif cat_score > 0:
            icon = "[.]"
        else:
            icon = "[ ]"

        bar_len = cat_score // 5
        bar = "#" * bar_len + "-" * (20 - bar_len)

        print(f"\n  {icon} {category}")
        print(f"       [{bar}] {cat_score}/100  ({count} findings)")

        for finding in cat.get("findings", []):
            print(f"         - {finding}")

    # Attack surface
    attack = profile.get("attack_surface", {})
    if attack:
        print(f"\n  Attack Surface:")
        for key, value in attack.items():
            label = key.replace("_", " ").title()
            print(f"    {label}: {value}")

    # Executive summary
    print(f"\n  Executive Summary:")
    summary = profile.get("executive_summary", "N/A")
    words = summary.split()
    line = "    "
    for word in words:
        if len(line) + len(word) + 1 > 70:
            print(line)
            line = "    " + word
        else:
            line += " " + word if line.strip() else "    " + word
    if line.strip():
        print(line)


def save_output(profile: dict, pipeline_metadata: dict, output_path: str):
    """Save risk profile JSON output."""
    report = {
        "agent_name": "DevSecOps Guardian - Risk Profiler Agent",
        "version": RISK_PROFILER_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repository": pipeline_metadata.get("repository", ""),
        "framework": "OWASP Top 10 2021",
        "overall_risk_score": profile.get("overall_risk_score", 0),
        "risk_level": profile.get("risk_level", "UNKNOWN"),
        "owasp_top_10": profile.get("owasp_top_10", []),
        "attack_surface": profile.get("attack_surface", {}),
        "executive_summary": profile.get("executive_summary", ""),
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  [*] Risk profile saved to: {output_path}")


async def main():
    parser = argparse.ArgumentParser(
        description="DevSecOps Guardian - Risk Profiler Agent"
    )
    parser.add_argument(
        "--scanner",
        type=str,
        default=DEFAULT_SCANNER_INPUT,
        help="Path to scanner JSON output",
    )
    parser.add_argument(
        "--analyzer",
        type=str,
        default=DEFAULT_ANALYZER_INPUT,
        help="Path to analyzer JSON output",
    )
    parser.add_argument(
        "--fixer",
        type=str,
        default=DEFAULT_FIXER_INPUT,
        help="Path to fixer JSON output",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=DEFAULT_RISK_OUTPUT,
        help="Output JSON file path",
    )

    args = parser.parse_args()

    # Header
    print(f"\n{'='*60}")
    print(f"  DevSecOps Guardian - Risk Profiler Agent")
    print(f"  Framework: OWASP Top 10 2021")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}\n")

    # Phase 1: Load all pipeline data
    print("[1/3] Loading pipeline data from upstream agents...")
    scanner_findings, confirmed_findings, fixer_results, pipeline_metadata = (
        load_pipeline_data(args.scanner, args.analyzer, args.fixer)
    )
    print(f"  Scanner findings: {len(scanner_findings)}")
    print(f"  Confirmed findings: {len(confirmed_findings)}")
    print(f"  Fix results: {len(fixer_results)}")

    if not confirmed_findings:
        print("\n  [OK] No confirmed findings - generating clean risk profile")
        profile = {
            "overall_risk_score": 0,
            "risk_level": "LOW",
            "owasp_top_10": [
                {
                    "category": f"A{str(i).zfill(2)}:2021",
                    "score": 0,
                    "findings_count": 0,
                    "findings": [],
                    "risk_factors": [],
                    "recommendations": [],
                }
                for i in range(1, 11)
            ],
            "attack_surface": {},
            "executive_summary": "No confirmed security vulnerabilities were identified. The application passed all security scans.",
        }
    else:
        # Phase 2: Generate risk profile via LLM
        print(f"\n[2/3] Generating OWASP Top 10 risk profile...")
        profile = await generate_risk_profile(
            scanner_findings, confirmed_findings, fixer_results, pipeline_metadata
        )

        if not profile:
            print("  [!] Failed to generate risk profile - check API connection")
            sys.exit(1)

    # Phase 3: Output
    print(f"\n[3/3] Generating risk profile report...")
    print_risk_profile(profile)
    save_output(profile, pipeline_metadata, args.output)


if __name__ == "__main__":
    asyncio.run(main())
