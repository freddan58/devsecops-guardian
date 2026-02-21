"""
DevSecOps Guardian - Scan Store Factory

Uses Azure Table Storage when AZURE_STORAGE_CONNECTION_STRING is set,
falls back to in-memory store for local development.
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from schemas import ScanStatus
from config import AZURE_STORAGE_CONNECTION_STRING, STORAGE_TABLE_NAME


class ScanRecord:
    """Represents a single scan execution."""

    def __init__(
        self,
        repository_path: str,
        ref: Optional[str] = None,
        dry_run: bool = False,
        parent_scan_id: Optional[str] = None,
    ):
        self.id = f"scan-{uuid.uuid4().hex[:12]}"
        self.status = ScanStatus.QUEUED
        self.repository_path = repository_path
        self.ref = ref
        self.dry_run = dry_run
        self.parent_scan_id = parent_scan_id
        self.scan_number = 1
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at
        self.current_stage: Optional[str] = None
        self.error: Optional[str] = None

        # Agent outputs (loaded from JSON files after each stage)
        self.scanner_output: Optional[dict] = None
        self.analyzer_output: Optional[dict] = None
        self.fixer_output: Optional[dict] = None
        self.risk_profile_output: Optional[dict] = None
        self.compliance_output: Optional[dict] = None

        # Stage tracking
        self.stages: dict[str, str] = {}

        # Re-scan comparison results
        self.comparison: Optional[dict] = None

    def update_status(self, status: ScanStatus, stage: Optional[str] = None):
        self.status = status
        self.updated_at = datetime.now(timezone.utc).isoformat()
        if stage:
            self.current_stage = stage

    def set_stage(self, stage: str, status: str):
        self.stages[stage] = status
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def set_error(self, error: str):
        self.status = ScanStatus.FAILED
        self.error = error
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def load_output(self, agent: str, file_path: str):
        if not os.path.exists(file_path):
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            setattr(self, f"{agent}_output", data)
        except (json.JSONDecodeError, OSError) as e:
            print(f"  [!] Failed to load {agent} output: {e}")

    @property
    def total_findings(self) -> int:
        if self.scanner_output:
            return self.scanner_output.get("total_findings", 0)
        return 0

    @property
    def confirmed_findings(self) -> int:
        if self.analyzer_output:
            return self.analyzer_output.get("confirmed_count", 0)
        return 0

    @property
    def fixed_findings(self) -> int:
        if self.fixer_output:
            return self.fixer_output.get("success_count", 0)
        return 0

    @property
    def risk_level(self) -> Optional[str]:
        if self.risk_profile_output:
            return self.risk_profile_output.get("risk_level")
        return None

    @property
    def compliance_rating(self) -> Optional[str]:
        if self.compliance_output:
            return self.compliance_output.get("overall_risk_rating")
        return None

    def to_summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status.value,
            "repository_path": self.repository_path,
            "ref": self.ref,
            "dry_run": self.dry_run,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "total_findings": self.total_findings,
            "confirmed_findings": self.confirmed_findings,
            "fixed_findings": self.fixed_findings,
            "risk_level": self.risk_level,
            "compliance_rating": self.compliance_rating,
            "current_stage": self.current_stage,
            "error": self.error,
            "parent_scan_id": self.parent_scan_id,
            "scan_number": self.scan_number,
        }

    def to_detail(self) -> dict[str, Any]:
        detail = self.to_summary()
        detail.update({
            "scanner_output": self.scanner_output,
            "analyzer_output": self.analyzer_output,
            "fixer_output": self.fixer_output,
            "risk_profile_output": self.risk_profile_output,
            "compliance_output": self.compliance_output,
            "stages": self.stages,
            "comparison": self.comparison,
        })
        return detail


class ScanStore:
    """In-memory store for scan records (local development fallback)."""

    def __init__(self):
        self._scans: dict[str, ScanRecord] = {}

    def create(
        self,
        repository_path: str,
        ref: Optional[str] = None,
        dry_run: bool = False,
        parent_scan_id: Optional[str] = None,
    ) -> ScanRecord:
        scan = ScanRecord(repository_path, ref, dry_run, parent_scan_id)

        # Calculate scan_number based on parent chain
        if parent_scan_id:
            parent = self.get(parent_scan_id)
            if parent:
                scan.scan_number = parent.scan_number + 1

        self._scans[scan.id] = scan
        return scan

    def get_history(self, scan_id: str) -> list["ScanRecord"]:
        """Get scan history chain (parent -> child)."""
        # Find root scan
        scan = self.get(scan_id)
        if not scan:
            return []

        # Walk up to find root
        root = scan
        while root.parent_scan_id:
            parent = self.get(root.parent_scan_id)
            if not parent:
                break
            root = parent

        # Walk down collecting chain
        chain = [root]
        current_id = root.id
        while True:
            child = next(
                (s for s in self._scans.values() if s.parent_scan_id == current_id),
                None,
            )
            if not child:
                break
            chain.append(child)
            current_id = child.id

        return chain

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        return self._scans.get(scan_id)

    def list_all(self) -> list[ScanRecord]:
        return sorted(
            self._scans.values(),
            key=lambda s: s.created_at,
            reverse=True,
        )

    def count(self) -> int:
        return len(self._scans)

    def save(self, scan: ScanRecord):
        """No-op for in-memory store (already in dict)."""
        self._scans[scan.id] = scan


def _create_store():
    """Factory: use Table Storage if configured, else in-memory."""
    if AZURE_STORAGE_CONNECTION_STRING:
        try:
            from table_store import TableScanStore
            store = TableScanStore(AZURE_STORAGE_CONNECTION_STRING, STORAGE_TABLE_NAME)
            if store._client:
                print("  [✓] Using Azure Table Storage for persistence")
                return store
        except ImportError:
            print("  [!] azure-data-tables not installed, using in-memory store")
        except Exception as e:
            print(f"  [!] Table Storage init failed: {e}, using in-memory store")

    print("  [i] Using in-memory store (data will not persist across restarts)")
    return ScanStore()


# Global store instance
scan_store = _create_store()
