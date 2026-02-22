"""
DevSecOps Guardian - Async Pipeline Runner

Runs agents as async subprocesses, same pattern as run_pipeline.py
but adapted for FastAPI BackgroundTasks.
"""

import asyncio
import os
import sys
import traceback

from config import (
    AGENTS_DIR,
    REPORTS_DIR,
    SCANNER_DIR,
    ANALYZER_DIR,
    FIXER_DIR,
    RISK_PROFILER_DIR,
    COMPLIANCE_DIR,
    PIPELINE_TIMEOUT,
)
from models import ScanRecord, scan_store
from schemas import ScanStatus


async def run_agent(
    agent_name: str,
    agent_dir: str,
    script: str,
    args: list[str],
    timeout: int = PIPELINE_TIMEOUT,
) -> tuple[int, str]:
    """Run a single agent as an async subprocess.

    Returns:
        Tuple of (return_code, stderr_output).
    """
    cmd = [sys.executable, script] + args
    print(f"  [>] Running {agent_name}: {' '.join(cmd)}")
    print(f"  [>] Working dir: {agent_dir}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=agent_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )

        # Print stdout for visibility
        if stdout:
            for line in stdout.decode("utf-8", errors="replace").splitlines():
                print(f"  [{agent_name}] {line}")

        stderr_text = stderr.decode("utf-8", errors="replace") if stderr else ""
        if stderr_text:
            for line in stderr_text.splitlines():
                print(f"  [{agent_name} ERR] {line}")

        return proc.returncode or 0, stderr_text

    except asyncio.TimeoutError:
        print(f"  [!!] {agent_name} timed out after {timeout}s")
        return -1, f"Agent timed out after {timeout} seconds"
    except Exception as e:
        print(f"  [!!] {agent_name} error: {e}")
        return -1, str(e)


def _make_finding_key(finding: dict) -> str:
    """Create a match key for comparing findings across scans."""
    cwe = finding.get("cwe", "")
    file = finding.get("file", "")
    line = finding.get("line", 0)
    line_bucket = (line // 10) * 10
    return f"{cwe}:{file}:{line_bucket}"


def _compare_scans(parent: ScanRecord, current: ScanRecord) -> dict:
    """Compare findings between parent and current scan."""
    parent_findings = {}
    if parent.analyzer_output:
        for f in parent.analyzer_output.get("findings", []):
            if f.get("verdict") == "CONFIRMED":
                key = _make_finding_key(f)
                parent_findings[key] = f

    current_findings = {}
    if current.analyzer_output:
        for f in current.analyzer_output.get("findings", []):
            if f.get("verdict") == "CONFIRMED":
                key = _make_finding_key(f)
                current_findings[key] = f

    comparison_findings = []
    new_count = 0
    resolved_count = 0
    persistent_count = 0

    for key, finding in current_findings.items():
        if key in parent_findings:
            status_change = "PERSISTENT"
            persistent_count += 1
        else:
            status_change = "NEW"
            new_count += 1
        comparison_findings.append({
            "scan_id": finding.get("scan_id", ""),
            "vulnerability": finding.get("vulnerability", ""),
            "cwe": finding.get("cwe", ""),
            "file": finding.get("file", ""),
            "severity": finding.get("severity", ""),
            "status_change": status_change,
        })

    for key, finding in parent_findings.items():
        if key not in current_findings:
            resolved_count += 1
            comparison_findings.append({
                "scan_id": finding.get("scan_id", ""),
                "vulnerability": finding.get("vulnerability", ""),
                "cwe": finding.get("cwe", ""),
                "file": finding.get("file", ""),
                "severity": finding.get("severity", ""),
                "status_change": "RESOLVED",
            })

    return {
        "current_scan_id": current.id,
        "parent_scan_id": parent.id,
        "new_findings": new_count,
        "resolved_findings": resolved_count,
        "persistent_findings": persistent_count,
        "regression_findings": 0,
        "findings": comparison_findings,
    }


async def run_pipeline(scan: ScanRecord):
    """Execute the full agent pipeline for a scan.

    Pipeline stages:
        1. Scanner  - Detect vulnerabilities
        2. Analyzer - Eliminate false positives
        3. Fixer    - Generate fix PRs
        4. Risk Profiler - OWASP risk scoring
        5. Compliance    - PCI-DSS 4.0 mapping
    """
    try:
        await _run_pipeline_inner(scan)
    except Exception as e:
        error_msg = f"Pipeline crashed: {type(e).__name__}: {e}"
        tb = traceback.format_exc()
        print(f"\n  [!!] {error_msg}")
        print(f"  [!!] Traceback:\n{tb}")
        try:
            scan.set_error(error_msg)
            scan_store.save(scan)
        except Exception as save_err:
            print(f"  [!!] Failed to save error state: {save_err}")


async def _run_pipeline_inner(scan: ScanRecord):
    """Inner pipeline logic (wrapped by run_pipeline for error handling)."""
    scan_dir = os.path.join(REPORTS_DIR, scan.id)
    os.makedirs(scan_dir, exist_ok=True)

    # Output file paths per agent
    scanner_out = os.path.join(scan_dir, "scanner-output.json")
    analyzer_out = os.path.join(scan_dir, "analyzer-output.json")
    fixer_out = os.path.join(scan_dir, "fixer-output.json")
    risk_out = os.path.join(scan_dir, "risk-profile-output.json")
    compliance_json = os.path.join(scan_dir, "compliance-output.json")
    compliance_md = os.path.join(scan_dir, "compliance-report.md")

    print(f"\n{'='*60}")
    print(f"  Pipeline started: {scan.id}")
    print(f"  Repository: {scan.repository_path}")
    print(f"  Reports dir: {scan_dir}")
    print(f"{'='*60}\n")

    # ---- STAGE 1: SCANNER ----
    scan.update_status(ScanStatus.SCANNING, "scanner")
    scan.set_stage("scanner", "running")
    scan_store.save(scan)

    scanner_args = ["--path", scan.repository_path, "--output", scanner_out]
    if scan.ref:
        scanner_args.extend(["--ref", scan.ref])

    rc, err = await run_agent("scanner", SCANNER_DIR, "scanner.py", scanner_args)
    if rc != 0:
        scan.set_stage("scanner", "failed")
        scan.set_error(f"Scanner failed: {err}")
        scan_store.save(scan)
        return
    scan.set_stage("scanner", "completed")
    scan.load_output("scanner", scanner_out)
    scan_store.save(scan)

    if not os.path.exists(scanner_out):
        scan.set_error("Scanner output file not found")
        scan_store.save(scan)
        return

    # ---- STAGE 2: ANALYZER ----
    scan.update_status(ScanStatus.ANALYZING, "analyzer")
    scan.set_stage("analyzer", "running")
    scan_store.save(scan)

    analyzer_args = ["--input", scanner_out, "--output", analyzer_out]
    if scan.ref:
        analyzer_args.extend(["--ref", scan.ref])

    rc, err = await run_agent("analyzer", ANALYZER_DIR, "analyzer.py", analyzer_args)
    if rc != 0:
        scan.set_stage("analyzer", "failed")
        scan.set_error(f"Analyzer failed: {err}")
        scan_store.save(scan)
        return
    scan.set_stage("analyzer", "completed")

    # Log file existence and size for debugging
    if os.path.exists(analyzer_out):
        fsize = os.path.getsize(analyzer_out)
        print(f"  [>] Analyzer output: {analyzer_out} ({fsize} bytes)")
    else:
        print(f"  [>] Analyzer output NOT found: {analyzer_out}")

    scan.load_output("analyzer", analyzer_out)
    print(f"  [>] analyzer_output loaded: {scan.analyzer_output is not None}")

    scan_store.save(scan)
    print(f"  [>] Scan saved after analyzer. Status: {scan.status.value}")

    if not os.path.exists(analyzer_out):
        scan.set_error("Analyzer output file not found")
        scan_store.save(scan)
        return

    print(f"  [>] Advancing to FIXER stage...")

    # ---- STAGE 3: FIXER ----
    scan.update_status(ScanStatus.FIXING, "fixer")
    scan.set_stage("fixer", "running")
    scan_store.save(scan)

    fixer_args = ["--input", analyzer_out, "--output", fixer_out]
    if scan.ref:
        fixer_args.extend(["--ref", scan.ref])
    if scan.dry_run:
        fixer_args.append("--dry-run")

    rc, err = await run_agent("fixer", FIXER_DIR, "fixer.py", fixer_args)
    if rc != 0:
        scan.set_stage("fixer", "failed")
        # Fixer failure is non-blocking
        print(f"  [!] Fixer failed (non-blocking): {err}")
    else:
        scan.set_stage("fixer", "completed")
        scan.load_output("fixer", fixer_out)
    scan_store.save(scan)

    # ---- STAGE 4: RISK PROFILER ----
    if os.path.exists(RISK_PROFILER_DIR):
        scan.update_status(ScanStatus.PROFILING, "risk-profiler")
        scan.set_stage("risk-profiler", "running")
        scan_store.save(scan)

        risk_args = [
            "--scanner", scanner_out,
            "--analyzer", analyzer_out,
            "--output", risk_out,
        ]
        if os.path.exists(fixer_out):
            risk_args.extend(["--fixer", fixer_out])

        rc, err = await run_agent(
            "risk-profiler", RISK_PROFILER_DIR, "risk_profiler.py", risk_args
        )
        if rc != 0:
            scan.set_stage("risk-profiler", "failed")
            print(f"  [!] Risk Profiler failed (non-blocking): {err}")
        else:
            scan.set_stage("risk-profiler", "completed")
            scan.load_output("risk_profile", risk_out)
    else:
        scan.set_stage("risk-profiler", "skipped")
    scan_store.save(scan)

    # ---- STAGE 5: COMPLIANCE ----
    scan.update_status(ScanStatus.COMPLIANCE_CHECK, "compliance")
    scan.set_stage("compliance", "running")
    scan_store.save(scan)

    compliance_args = [
        "--scanner", scanner_out,
        "--analyzer", analyzer_out,
        "--output-json", compliance_json,
        "--output-md", compliance_md,
    ]
    if os.path.exists(fixer_out):
        compliance_args.extend(["--fixer", fixer_out])

    rc, err = await run_agent(
        "compliance", COMPLIANCE_DIR, "compliance.py", compliance_args
    )
    if rc != 0:
        scan.set_stage("compliance", "failed")
        print(f"  [!] Compliance failed (non-blocking): {err}")
    else:
        scan.set_stage("compliance", "completed")
        scan.load_output("compliance", compliance_json)

    # ---- COMPARISON (if re-scan) ----
    if scan.parent_scan_id:
        parent = scan_store.get(scan.parent_scan_id)
        if parent and parent.analyzer_output:
            comparison = _compare_scans(parent, scan)
            scan.comparison = comparison
            print(f"  [>] Re-scan comparison: {comparison.get('new_findings', 0)} new, "
                  f"{comparison.get('resolved_findings', 0)} resolved, "
                  f"{comparison.get('persistent_findings', 0)} persistent")

    # ---- DONE ----
    scan.update_status(ScanStatus.COMPLETED)
    scan.current_stage = None
    scan_store.save(scan)

    print(f"\n{'='*60}")
    print(f"  Pipeline completed: {scan.id}")
    print(f"  Status: {scan.status.value}")
    print(f"  Findings: {scan.total_findings} total, "
          f"{scan.confirmed_findings} confirmed, "
          f"{scan.fixed_findings} fixed")
    print(f"{'='*60}\n")
