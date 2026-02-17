"""
DevSecOps Guardian - Pipeline Orchestrator
==========================================
Runs the full 4-agent security pipeline in sequence:
  Scanner -> Analyzer -> Fixer -> Compliance

Usage:
    python run_pipeline.py                           # Full pipeline on demo-app
    python run_pipeline.py --path demo-app           # Scan specific path
    python run_pipeline.py --pr 7                    # Scan a PR
    python run_pipeline.py --dry-run                 # Skip GitHub writes (no branches/PRs)
    python run_pipeline.py --skip-fixer              # Skip fix generation
    python run_pipeline.py --skip-compliance         # Skip compliance report

Environment:
    Each agent reads its own .env file from its directory.
    Ensure all agents/*/  .env files are configured before running.
"""

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime, timezone


# Directories
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
AGENTS_DIR = os.path.join(ROOT_DIR, "agents")

# Agent configurations
AGENTS = {
    "scanner": {
        "dir": os.path.join(AGENTS_DIR, "scanner"),
        "script": "scanner.py",
        "output": os.path.join(AGENTS_DIR, "scanner", "reports", "scanner-output.json"),
        "description": "LLM-based code security scanner",
    },
    "analyzer": {
        "dir": os.path.join(AGENTS_DIR, "analyzer"),
        "script": "analyzer.py",
        "output": os.path.join(AGENTS_DIR, "analyzer", "reports", "analyzer-output.json"),
        "description": "Contextual false-positive eliminator",
    },
    "fixer": {
        "dir": os.path.join(AGENTS_DIR, "fixer"),
        "script": "fixer.py",
        "output": os.path.join(AGENTS_DIR, "fixer", "reports", "fixer-output.json"),
        "description": "Automated security fix generator",
    },
    "compliance": {
        "dir": os.path.join(AGENTS_DIR, "compliance"),
        "script": "compliance.py",
        "output_json": os.path.join(AGENTS_DIR, "compliance", "reports", "compliance-output.json"),
        "output_md": os.path.join(AGENTS_DIR, "compliance", "reports", "compliance-report.md"),
        "description": "PCI-DSS 4.0 compliance report generator",
    },
}


def print_banner():
    """Print pipeline banner."""
    now = datetime.now(timezone.utc).isoformat()
    print(f"\n{'='*70}")
    print(f"  DevSecOps Guardian - Multi-Agent Security Pipeline")
    print(f"  Agents: Scanner -> Analyzer -> Fixer -> Compliance")
    print(f"  Time: {now}")
    print(f"{'='*70}\n")


def print_stage(stage_num: int, total: int, name: str, description: str):
    """Print stage header."""
    print(f"\n{'='*70}")
    print(f"  STAGE {stage_num}/{total}: {name.upper()}")
    print(f"  {description}")
    print(f"{'='*70}\n")


def run_agent(agent_name: str, extra_args: list[str] = None) -> int:
    """Run an agent as a subprocess.

    Args:
        agent_name: Key in AGENTS dict.
        extra_args: Additional CLI arguments for the agent.

    Returns:
        Process return code (0 = success).
    """
    agent = AGENTS[agent_name]
    cmd = [sys.executable, agent["script"]]
    if extra_args:
        cmd.extend(extra_args)

    print(f"  [>] Running: {' '.join(cmd)}")
    print(f"  [>] Working dir: {agent['dir']}")
    print()

    start_time = time.time()

    result = subprocess.run(
        cmd,
        cwd=agent["dir"],
        env={**os.environ},
    )

    elapsed = time.time() - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)

    if result.returncode == 0:
        print(f"\n  [OK] {agent_name.upper()} completed in {minutes}m {seconds}s")
    else:
        print(f"\n  [!!] {agent_name.upper()} FAILED (exit code {result.returncode}) after {minutes}m {seconds}s")

    return result.returncode


def main():
    parser = argparse.ArgumentParser(
        description="DevSecOps Guardian - Multi-Agent Security Pipeline"
    )
    parser.add_argument(
        "--path", type=str, default="demo-app",
        help="Repository path to scan (default: demo-app)"
    )
    parser.add_argument(
        "--pr", type=int,
        help="PR number to scan (overrides --path)"
    )
    parser.add_argument(
        "--ref", type=str,
        help="Branch or commit SHA for reading source files"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Skip GitHub writes (no branches, commits, or PRs)"
    )
    parser.add_argument(
        "--skip-fixer", action="store_true",
        help="Skip the Fixer agent (no auto-fix PRs)"
    )
    parser.add_argument(
        "--skip-compliance", action="store_true",
        help="Skip the Compliance agent (no PCI-DSS report)"
    )

    args = parser.parse_args()

    print_banner()

    # Determine total stages
    total_stages = 2  # scanner + analyzer always run
    if not args.skip_fixer:
        total_stages += 1
    if not args.skip_compliance:
        total_stages += 1

    pipeline_start = time.time()
    stage = 0
    failed = False

    # ---- STAGE 1: SCANNER ----
    stage += 1
    print_stage(stage, total_stages, "Scanner", AGENTS["scanner"]["description"])

    scanner_args = []
    if args.pr:
        scanner_args.extend(["--pr", str(args.pr)])
    elif args.path:
        scanner_args.extend(["--path", args.path])
    if args.ref:
        scanner_args.extend(["--ref", args.ref])

    rc = run_agent("scanner", scanner_args)
    if rc != 0:
        print("\n  [!!] Scanner failed - pipeline cannot continue")
        sys.exit(1)

    # Check scanner output exists
    if not os.path.exists(AGENTS["scanner"]["output"]):
        print(f"\n  [!!] Scanner output not found: {AGENTS['scanner']['output']}")
        sys.exit(1)

    # ---- STAGE 2: ANALYZER ----
    stage += 1
    print_stage(stage, total_stages, "Analyzer", AGENTS["analyzer"]["description"])

    analyzer_args = [
        "--input", AGENTS["scanner"]["output"],
    ]
    if args.ref:
        analyzer_args.extend(["--ref", args.ref])

    rc = run_agent("analyzer", analyzer_args)
    if rc != 0:
        print("\n  [!!] Analyzer failed - pipeline cannot continue")
        sys.exit(1)

    if not os.path.exists(AGENTS["analyzer"]["output"]):
        print(f"\n  [!!] Analyzer output not found: {AGENTS['analyzer']['output']}")
        sys.exit(1)

    # ---- STAGE 3: FIXER (optional) ----
    if not args.skip_fixer:
        stage += 1
        print_stage(stage, total_stages, "Fixer", AGENTS["fixer"]["description"])

        fixer_args = [
            "--input", AGENTS["analyzer"]["output"],
        ]
        if args.ref:
            fixer_args.extend(["--ref", args.ref])
        if args.dry_run:
            fixer_args.append("--dry-run")

        rc = run_agent("fixer", fixer_args)
        if rc != 0:
            print("\n  [!] Fixer failed - continuing to compliance (non-blocking)")
            failed = True

    # ---- STAGE 4: COMPLIANCE (optional) ----
    if not args.skip_compliance:
        stage += 1
        print_stage(stage, total_stages, "Compliance", AGENTS["compliance"]["description"])

        compliance_args = [
            "--scanner", AGENTS["scanner"]["output"],
            "--analyzer", AGENTS["analyzer"]["output"],
        ]
        # Only pass fixer output if fixer ran
        if not args.skip_fixer and os.path.exists(AGENTS["fixer"]["output"]):
            compliance_args.extend(["--fixer", AGENTS["fixer"]["output"]])

        rc = run_agent("compliance", compliance_args)
        if rc != 0:
            print("\n  [!] Compliance failed - report not generated")
            failed = True

    # ---- SUMMARY ----
    pipeline_elapsed = time.time() - pipeline_start
    minutes = int(pipeline_elapsed // 60)
    seconds = int(pipeline_elapsed % 60)

    print(f"\n{'='*70}")
    print(f"  PIPELINE COMPLETE")
    print(f"  Total time: {minutes}m {seconds}s")
    print(f"{'='*70}")
    print()
    print("  Reports generated:")
    print(f"    Scanner:    {AGENTS['scanner']['output']}")
    print(f"    Analyzer:   {AGENTS['analyzer']['output']}")
    if not args.skip_fixer:
        print(f"    Fixer:      {AGENTS['fixer']['output']}")
    if not args.skip_compliance:
        print(f"    Compliance: {AGENTS['compliance']['output_json']}")
        print(f"    Report:     {AGENTS['compliance']['output_md']}")
    print()

    if failed:
        print("  [!] Some stages had errors - review output above")
        sys.exit(1)
    else:
        print("  [OK] All stages completed successfully")


if __name__ == "__main__":
    main()
