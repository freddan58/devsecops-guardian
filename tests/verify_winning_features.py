#!/usr/bin/env python3
"""
DevSecOps Guardian - Winning Features Verification Suite
=========================================================

Comprehensive end-to-end tests for the 4 winning features:
1. Vulnerability Detail Modal (code_context, analysis_reasoning, best_practices, fixed_code)
2. Fix Status Resolution (FIX_GENERATED status, fixed_code storage)
3. Re-Scan with History (parent_scan_id, comparison, scan history)
4. Best Practices Analysis (practices endpoint, maturity score)

Usage:
    # Against production
    python tests/verify_winning_features.py

    # Against local
    python tests/verify_winning_features.py --api-url http://localhost:8000

    # Skip scan creation (use existing scan)
    python tests/verify_winning_features.py --scan-id <existing-scan-id>

    # Quick mode (skip waiting for scan completion)
    python tests/verify_winning_features.py --quick

    # Verbose mode
    python tests/verify_winning_features.py -v
"""

import argparse
import json
import sys
import time
from datetime import datetime
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


# ─── Configuration ────────────────────────────────────────────

PROD_API_URL = "https://ca-api-gateway.agreeablesand-6566841b.eastus.azurecontainerapps.io"
PROD_DASHBOARD_URL = "https://ca-dashboard.agreeablesand-6566841b.eastus.azurecontainerapps.io"
DEFAULT_REPO = "demo-app"
SCAN_TIMEOUT = 600  # 10 minutes max wait for scan
POLL_INTERVAL = 5   # seconds between poll


# ─── Utilities ────────────────────────────────────────────────

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def log(msg: str, color: str = ""):
    timestamp = datetime.now().strftime("%H:%M:%S")
    prefix = f"{Colors.CYAN}[{timestamp}]{Colors.END} "
    if color:
        print(f"{prefix}{color}{msg}{Colors.END}")
    else:
        print(f"{prefix}{msg}")


def log_pass(test_name: str, detail: str = ""):
    extra = f" — {detail}" if detail else ""
    log(f"  ✅ PASS: {test_name}{extra}", Colors.GREEN)


def log_fail(test_name: str, detail: str = ""):
    extra = f" — {detail}" if detail else ""
    log(f"  ❌ FAIL: {test_name}{extra}", Colors.RED)


def log_skip(test_name: str, detail: str = ""):
    extra = f" — {detail}" if detail else ""
    log(f"  ⏭️  SKIP: {test_name}{extra}", Colors.YELLOW)


def log_info(msg: str):
    log(f"  ℹ️  {msg}", Colors.BLUE)


def log_section(title: str):
    log(f"\n{'='*60}", Colors.BOLD)
    log(f"  {title}", Colors.BOLD)
    log(f"{'='*60}", Colors.BOLD)


def api_call(base_url: str, path: str, method: str = "GET", body: dict = None) -> tuple[int, Any]:
    """Make an API call and return (status_code, parsed_json)."""
    url = f"{base_url}{path}"
    headers = {"Content-Type": "application/json"}
    data = json.dumps(body).encode() if body else None

    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except HTTPError as e:
        try:
            error_body = json.loads(e.read().decode())
        except Exception:
            error_body = {"detail": str(e)}
        return e.code, error_body
    except URLError as e:
        return 0, {"detail": f"Connection error: {e.reason}"}
    except Exception as e:
        return 0, {"detail": str(e)}


# ─── Test Runner ──────────────────────────────────────────────

class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.errors: list[str] = []

    def add_pass(self, name: str, detail: str = ""):
        self.passed += 1
        log_pass(name, detail)

    def add_fail(self, name: str, detail: str = ""):
        self.failed += 1
        self.errors.append(f"{name}: {detail}")
        log_fail(name, detail)

    def add_skip(self, name: str, detail: str = ""):
        self.skipped += 1
        log_skip(name, detail)

    def check(self, name: str, condition: bool, pass_detail: str = "", fail_detail: str = ""):
        if condition:
            self.add_pass(name, pass_detail)
        else:
            self.add_fail(name, fail_detail)
        return condition

    def summary(self) -> int:
        total = self.passed + self.failed + self.skipped
        log_section("TEST SUMMARY")
        log(f"  Total:   {total}")
        log(f"  Passed:  {self.passed}", Colors.GREEN)
        log(f"  Failed:  {self.failed}", Colors.RED if self.failed else "")
        log(f"  Skipped: {self.skipped}", Colors.YELLOW if self.skipped else "")

        if self.errors:
            log("\n  Failures:", Colors.RED)
            for err in self.errors:
                log(f"    • {err}", Colors.RED)

        if self.failed == 0:
            log(f"\n  🏆 ALL TESTS PASSED!", Colors.GREEN + Colors.BOLD)
        else:
            log(f"\n  ⚠️  {self.failed} TEST(S) FAILED", Colors.RED + Colors.BOLD)

        return 1 if self.failed > 0 else 0


# ─── Test Groups ──────────────────────────────────────────────

def test_health(api_url: str, results: TestResults) -> bool:
    """Test 0: API Health Check"""
    log_section("TEST 0: API Health Check")

    status, data = api_call(api_url, "/api/health")

    results.check("API responds", status == 200,
                  f"status={status}", f"status={status}, detail={data}")

    if status != 200:
        return False

    results.check("Status is healthy", data.get("status") == "healthy",
                  f"status={data.get('status')}", f"status={data.get('status')}")

    agents = data.get("agents", {})
    expected_agents = ["scanner", "analyzer", "fixer", "risk-profiler", "compliance"]
    for agent in expected_agents:
        results.check(f"Agent '{agent}' registered",
                      agent in agents,
                      agents.get(agent, ""),
                      f"Missing from agents: {list(agents.keys())}")

    return True


def test_create_scan(api_url: str, results: TestResults, dry_run: bool = True,
                     parent_scan_id: str = None) -> Optional[str]:
    """Create a scan and return scan_id."""
    log_section("TEST 1: Create Scan")

    body = {"repository_path": DEFAULT_REPO, "dry_run": dry_run}
    if parent_scan_id:
        body["parent_scan_id"] = parent_scan_id

    status, data = api_call(api_url, "/api/scans", method="POST", body=body)

    if not results.check("Scan created", status == 200,
                         f"id={data.get('id')}", f"status={status}, detail={data}"):
        return None

    scan_id = data.get("id")
    results.check("Scan has ID", bool(scan_id), scan_id)
    results.check("Status is QUEUED or SCANNING",
                  data.get("status") in ["QUEUED", "SCANNING"],
                  data.get("status"))

    # Feature 3: parent_scan_id support
    if parent_scan_id:
        results.check("parent_scan_id set", data.get("parent_scan_id") == parent_scan_id,
                      data.get("parent_scan_id"), f"Expected {parent_scan_id}")
        results.check("scan_number > 1", data.get("scan_number", 0) > 1,
                      f"scan_number={data.get('scan_number')}")
    else:
        results.check("scan_number is 1", data.get("scan_number") == 1,
                      f"scan_number={data.get('scan_number')}")

    return scan_id


def test_wait_for_completion(api_url: str, scan_id: str, results: TestResults) -> Optional[dict]:
    """Wait for scan to complete and return scan detail."""
    log_section("TEST 2: Wait for Scan Completion")

    start = time.time()
    last_stage = ""

    while time.time() - start < SCAN_TIMEOUT:
        status, data = api_call(api_url, f"/api/scans/{scan_id}")

        if status != 200:
            results.add_fail("Poll scan", f"status={status}")
            return None

        current_stage = data.get("current_stage", "")
        scan_status = data.get("status", "")

        if current_stage != last_stage:
            elapsed = int(time.time() - start)
            log_info(f"[{elapsed}s] Stage: {current_stage} | Status: {scan_status}")
            last_stage = current_stage

        if scan_status == "COMPLETED":
            elapsed = int(time.time() - start)
            results.add_pass("Scan completed", f"in {elapsed}s")
            return data

        if scan_status == "FAILED":
            results.add_fail("Scan completed", f"FAILED after {int(time.time() - start)}s — error: {data.get('error')}")
            return data  # Still return data for partial testing

        time.sleep(POLL_INTERVAL)

    results.add_fail("Scan completed", f"Timeout after {SCAN_TIMEOUT}s")
    return None


def test_scan_detail_fields(scan_data: dict, results: TestResults, is_rescan: bool = False):
    """Test scan detail has all expected fields."""
    log_section("TEST 3: Scan Detail Fields")

    # Basic fields
    for field in ["id", "status", "repository_path", "stages", "total_findings",
                  "confirmed_findings", "fixed_findings"]:
        results.check(f"Field '{field}' present", field in scan_data,
                      f"{field}={scan_data.get(field)}")

    # New fields
    results.check("parent_scan_id field present", "parent_scan_id" in scan_data,
                  f"parent_scan_id={scan_data.get('parent_scan_id')}")
    results.check("scan_number field present", "scan_number" in scan_data,
                  f"scan_number={scan_data.get('scan_number')}")

    # Outputs populated
    for output in ["scanner_output", "analyzer_output", "fixer_output",
                   "risk_profile_output", "compliance_output"]:
        has_output = scan_data.get(output) is not None
        if scan_data.get("status") == "COMPLETED":
            results.check(f"Output '{output}' populated", has_output,
                          "present", "missing")
        else:
            if has_output:
                results.add_pass(f"Output '{output}' populated", "present")
            else:
                results.add_skip(f"Output '{output}'", "scan not completed")

    # Feature 3: Comparison field
    if is_rescan:
        results.check("comparison field present for re-scan",
                      "comparison" in scan_data,
                      f"comparison={json.dumps(scan_data.get('comparison', {}))[:100]}")


def test_findings_enrichment(api_url: str, scan_id: str, results: TestResults):
    """Test findings have all new enrichment fields."""
    log_section("TEST 4: Findings Enrichment (Feature 1 + 2)")

    status, data = api_call(api_url, f"/api/scans/{scan_id}/findings")

    if not results.check("Findings endpoint responds", status == 200,
                         f"total={data.get('total')}", f"status={status}"):
        return

    findings = data.get("findings", [])
    results.check("Has findings", len(findings) > 0, f"count={len(findings)}")

    if not findings:
        results.add_skip("Finding field checks", "No findings to test")
        return

    f = findings[0]  # Test first finding
    log_info(f"Testing finding: {f.get('vulnerability', 'unknown')} in {f.get('file', 'unknown')}")

    # Original fields
    for field in ["scan_id", "file", "line", "vulnerability", "cwe", "severity",
                  "description", "evidence", "recommendation", "verdict",
                  "exploitability_score", "fix_status"]:
        results.check(f"Original field '{field}'", field in f,
                      f"{field}={str(f.get(field, ''))[:60]}")

    # ── Feature 1: Vulnerability Detail Modal fields ──

    # code_context (from Scanner)
    results.check("code_context field present", "code_context" in f,
                  f"type={type(f.get('code_context')).__name__}")

    if f.get("code_context"):
        cc = f["code_context"]
        results.check("code_context.vulnerable_code present",
                      bool(cc.get("vulnerable_code")),
                      f"length={len(cc.get('vulnerable_code', ''))}")
        results.check("code_context.related_files is list",
                      isinstance(cc.get("related_files"), list),
                      f"count={len(cc.get('related_files', []))}")

    # analysis_reasoning (from Analyzer)
    results.check("analysis_reasoning field present", "analysis_reasoning" in f,
                  f"length={len(str(f.get('analysis_reasoning', '')))}")

    if f.get("verdict") == "CONFIRMED":
        results.check("analysis_reasoning non-empty for CONFIRMED",
                      bool(f.get("analysis_reasoning")),
                      f"starts with: {str(f.get('analysis_reasoning', ''))[:80]}...")

    # best_practices_analysis (from Analyzer)
    results.check("best_practices_analysis field present",
                  "best_practices_analysis" in f,
                  f"type={type(f.get('best_practices_analysis')).__name__}")

    if f.get("best_practices_analysis"):
        bpa = f["best_practices_analysis"]
        results.check("violated_practices is list",
                      isinstance(bpa.get("violated_practices"), list),
                      f"count={len(bpa.get('violated_practices', []))}")
        results.check("followed_practices is list",
                      isinstance(bpa.get("followed_practices"), list),
                      f"count={len(bpa.get('followed_practices', []))}")

        # Validate violation structure
        if bpa.get("violated_practices"):
            vp = bpa["violated_practices"][0]
            for vp_field in ["practice", "category", "current_state", "recommended_state"]:
                results.check(f"violated_practice.{vp_field}",
                              vp_field in vp, f"{vp.get(vp_field, '')[:50]}")

    # ── Feature 2: Fix Status fields ──

    results.check("fixed_code field present", "fixed_code" in f,
                  f"length={len(str(f.get('fixed_code', '')))}")
    results.check("fix_explanation field present", "fix_explanation" in f,
                  f"length={len(str(f.get('fix_explanation', '')))}")
    results.check("fix_error field present", "fix_error" in f,
                  f"value={str(f.get('fix_error', ''))[:50]}")

    # Additional enrichment fields
    results.check("auth_context field present", "auth_context" in f,
                  f"value={str(f.get('auth_context', ''))[:60]}")
    results.check("data_sensitivity field present", "data_sensitivity" in f,
                  f"value={str(f.get('data_sensitivity', ''))[:60]}")

    # Fix status values
    valid_statuses = ["SUCCESS", "FAILED", "DRY_RUN", "PENDING", "FIX_GENERATED", "PARTIAL", "N/A"]
    results.check("fix_status is valid enum",
                  f.get("fix_status") in valid_statuses,
                  f"fix_status={f.get('fix_status')}",
                  f"fix_status={f.get('fix_status')}, expected one of {valid_statuses}")

    # Check all findings for FIX_GENERATED status
    fix_statuses = set(finding.get("fix_status") for finding in findings)
    log_info(f"Fix statuses across all findings: {fix_statuses}")

    # ── Feature 3: Re-scan status_change ──
    results.check("status_change field present", "status_change" in f,
                  f"value={f.get('status_change')}")


def test_scan_history(api_url: str, scan_id: str, results: TestResults):
    """Test scan history endpoint (Feature 3)."""
    log_section("TEST 5: Scan History (Feature 3)")

    status, data = api_call(api_url, f"/api/scans/{scan_id}/history")

    if not results.check("History endpoint responds", status == 200,
                         f"count={len(data) if isinstance(data, list) else 'N/A'}",
                         f"status={status}, detail={data}"):
        return

    results.check("History is a list", isinstance(data, list), f"count={len(data)}")
    results.check("History contains current scan",
                  any(s.get("id") == scan_id for s in data),
                  f"found in {len(data)} entries")


def test_practices_endpoint(api_url: str, scan_id: str, results: TestResults):
    """Test practices endpoint (Feature 4)."""
    log_section("TEST 6: Best Practices Endpoint (Feature 4)")

    status, data = api_call(api_url, f"/api/scans/{scan_id}/practices")

    if not results.check("Practices endpoint responds", status == 200,
                         f"maturity_score={data.get('maturity_score')}",
                         f"status={status}, detail={data}"):
        return

    # Core fields
    results.check("scan_id matches", data.get("scan_id") == scan_id,
                  data.get("scan_id"))
    results.check("maturity_score is number",
                  isinstance(data.get("maturity_score"), (int, float)),
                  f"score={data.get('maturity_score')}")
    results.check("maturity_score in range 0-100",
                  0 <= data.get("maturity_score", -1) <= 100,
                  f"score={data.get('maturity_score')}")

    # Totals
    results.check("total_violations is number",
                  isinstance(data.get("total_violations"), int),
                  f"count={data.get('total_violations')}")
    results.check("total_followed is number",
                  isinstance(data.get("total_followed"), int),
                  f"count={data.get('total_followed')}")

    # Categories
    categories = data.get("categories", {})
    results.check("categories is dict", isinstance(categories, dict),
                  f"keys={list(categories.keys())[:5]}")

    if categories:
        first_cat = list(categories.values())[0]
        results.check("category has violations count",
                      "violations" in first_cat,
                      f"violations={first_cat.get('violations')}")
        results.check("category has followed count",
                      "followed" in first_cat,
                      f"followed={first_cat.get('followed')}")

    # Top violations
    top_violations = data.get("top_violations", [])
    results.check("top_violations is list", isinstance(top_violations, list),
                  f"count={len(top_violations)}")

    if top_violations:
        tv = top_violations[0]
        for field in ["practice", "category", "current_state", "recommended_state"]:
            results.check(f"top_violation.{field}",
                          field in tv, f"{tv.get(field, '')[:50]}")

    # Top followed
    top_followed = data.get("top_followed", [])
    results.check("top_followed is list", isinstance(top_followed, list),
                  f"count={len(top_followed)}")

    # Anti-patterns
    anti_patterns = data.get("anti_patterns", [])
    results.check("anti_patterns is list", isinstance(anti_patterns, list),
                  f"count={len(anti_patterns)}")

    if anti_patterns:
        ap = anti_patterns[0]
        results.check("anti_pattern has practice", "practice" in ap, ap.get("practice"))
        results.check("anti_pattern has occurrences >= 2",
                      ap.get("occurrences", 0) >= 2,
                      f"occurrences={ap.get('occurrences')}")


def test_rescan_workflow(api_url: str, original_scan_id: str, results: TestResults) -> Optional[str]:
    """Test full re-scan workflow (Feature 3)."""
    log_section("TEST 7: Re-Scan Workflow (Feature 3)")

    # Create re-scan
    body = {
        "repository_path": DEFAULT_REPO,
        "dry_run": True,
        "parent_scan_id": original_scan_id,
    }
    status, data = api_call(api_url, "/api/scans", method="POST", body=body)

    if not results.check("Re-scan created", status == 200,
                         f"id={data.get('id')}", f"status={status}, detail={data}"):
        return None

    rescan_id = data.get("id")
    results.check("Re-scan has parent_scan_id", data.get("parent_scan_id") == original_scan_id,
                  f"parent={data.get('parent_scan_id')}")
    results.check("Re-scan scan_number > 1", data.get("scan_number", 0) > 1,
                  f"scan_number={data.get('scan_number')}")

    return rescan_id


def test_dashboard_accessible(dashboard_url: str, results: TestResults):
    """Test dashboard is accessible."""
    log_section("TEST 8: Dashboard Accessibility")

    try:
        req = Request(dashboard_url, method="GET")
        with urlopen(req, timeout=15) as resp:
            status = resp.status
            content = resp.read().decode()[:500]

        results.check("Dashboard responds", status == 200,
                      f"status={status}")
        results.check("Dashboard returns HTML",
                      "<!DOCTYPE html>" in content or "<html" in content,
                      "HTML content detected")
        results.check("Dashboard has Next.js markers",
                      "__next" in content or "next" in content.lower(),
                      "Next.js markers found")
    except Exception as e:
        results.add_fail("Dashboard accessible", str(e))


def test_api_routes(api_url: str, results: TestResults):
    """Test all API routes exist."""
    log_section("TEST 9: API Route Verification")

    # Test that key routes respond (even with 404 for missing scan)
    routes_to_test = [
        ("/api/health", "GET", 200),
        ("/api/scans", "GET", 200),
    ]

    for path, method, expected_status in routes_to_test:
        status, _ = api_call(api_url, path, method=method)
        results.check(f"Route {method} {path}",
                      status == expected_status,
                      f"status={status}",
                      f"expected={expected_status}, got={status}")

    # Test scan-specific routes respond (404 for fake scan is ok — means route exists)
    fake_id = "nonexistent-scan-id"
    scan_routes = [
        f"/api/scans/{fake_id}",
        f"/api/scans/{fake_id}/findings",
        f"/api/scans/{fake_id}/risk-profile",
        f"/api/scans/{fake_id}/compliance",
        f"/api/scans/{fake_id}/practices",
        f"/api/scans/{fake_id}/history",
    ]

    for path in scan_routes:
        status, _ = api_call(api_url, path)
        # 404 means route exists but scan not found — that's correct
        results.check(f"Route GET {path.replace(fake_id, '{{id}}')}",
                      status in [200, 404],
                      f"status={status}",
                      f"expected 200 or 404, got {status} (route may not exist)")


def test_list_scans_schema(api_url: str, results: TestResults) -> Optional[str]:
    """Test list scans and verify new fields in schema."""
    log_section("TEST 10: List Scans Schema Verification")

    status, data = api_call(api_url, "/api/scans")

    if not results.check("List scans responds", status == 200,
                         f"count={len(data) if isinstance(data, list) else 'N/A'}"):
        return None

    if not data or not isinstance(data, list) or len(data) == 0:
        results.add_skip("Scan schema check", "No scans found")
        return None

    scan = data[0]

    # New fields from Feature 3
    results.check("ScanSummary has parent_scan_id", "parent_scan_id" in scan,
                  f"parent_scan_id={scan.get('parent_scan_id')}")
    results.check("ScanSummary has scan_number", "scan_number" in scan,
                  f"scan_number={scan.get('scan_number')}")

    # Find a completed scan for subsequent tests
    completed = [s for s in data if s.get("status") == "COMPLETED"]
    if completed:
        log_info(f"Found {len(completed)} completed scan(s)")
        return completed[0]["id"]
    else:
        log_info("No completed scans found")
        return None


# ─── Main ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DevSecOps Guardian — Winning Features Verification Suite"
    )
    parser.add_argument("--api-url", default=PROD_API_URL,
                        help=f"API base URL (default: {PROD_API_URL})")
    parser.add_argument("--dashboard-url", default=PROD_DASHBOARD_URL,
                        help=f"Dashboard URL (default: {PROD_DASHBOARD_URL})")
    parser.add_argument("--scan-id", default=None,
                        help="Use existing scan ID instead of creating new")
    parser.add_argument("--quick", action="store_true",
                        help="Quick mode — skip scan creation and waiting")
    parser.add_argument("--no-rescan", action="store_true",
                        help="Skip re-scan test (saves time)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    args = parser.parse_args()

    results = TestResults()

    log_section("DevSecOps Guardian — Winning Features Verification")
    log(f"  API:       {args.api_url}")
    log(f"  Dashboard: {args.dashboard_url}")
    log(f"  Mode:      {'Quick' if args.quick else 'Full'}")
    log(f"  Scan ID:   {args.scan_id or 'will create new'}")
    log(f"  Time:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Test 0: Health ──
    if not test_health(args.api_url, results):
        log("\n⛔ API is not reachable. Cannot continue.", Colors.RED)
        return results.summary()

    # ── Test 9: Route verification ──
    test_api_routes(args.api_url, results)

    # ── Test 8: Dashboard ──
    test_dashboard_accessible(args.dashboard_url, results)

    # ── Test 10: List scans + find existing ──
    existing_scan_id = test_list_scans_schema(args.api_url, results)

    # Determine which scan to use for detailed tests
    scan_id = args.scan_id or existing_scan_id

    if args.quick and not scan_id:
        log("\n⚠️  Quick mode: no existing completed scan found. Skipping detailed tests.", Colors.YELLOW)
        return results.summary()

    if not args.quick and not args.scan_id:
        # Create a new scan
        scan_id = test_create_scan(args.api_url, results)
        if scan_id:
            scan_data = test_wait_for_completion(args.api_url, scan_id, results)
            if scan_data:
                test_scan_detail_fields(scan_data, results)
        else:
            log("\n⚠️  Could not create scan. Using existing if available.", Colors.YELLOW)
            scan_id = existing_scan_id

    if not scan_id:
        log("\n⚠️  No scan available for detailed tests.", Colors.YELLOW)
        return results.summary()

    log_info(f"Using scan ID: {scan_id}")

    # ── Test 3: Scan detail fields (if we haven't already) ──
    if args.scan_id or args.quick:
        status, scan_data = api_call(args.api_url, f"/api/scans/{scan_id}")
        if status == 200:
            test_scan_detail_fields(scan_data, results)

    # ── Test 4: Findings enrichment ──
    test_findings_enrichment(args.api_url, scan_id, results)

    # ── Test 5: Scan history ──
    test_scan_history(args.api_url, scan_id, results)

    # ── Test 6: Practices endpoint ──
    test_practices_endpoint(args.api_url, scan_id, results)

    # ── Test 7: Re-scan workflow ──
    if not args.no_rescan and not args.quick:
        rescan_id = test_rescan_workflow(args.api_url, scan_id, results)
        if rescan_id:
            log_info(f"Re-scan created: {rescan_id}")
            log_info("Re-scan queued — full comparison available after completion")
    else:
        results.add_skip("Re-scan workflow", "Skipped (--quick or --no-rescan)")

    # ── Summary ──
    return results.summary()


if __name__ == "__main__":
    sys.exit(main())
