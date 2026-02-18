"""
DevSecOps Guardian - In-Memory Scan Store

Simple dict-based store for hackathon. In production, this would be
a database (PostgreSQL, CosmosDB, etc.).
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from schemas import ScanStatus


class ScanRecord:
    """Represents a single scan execution."""

    def __init__(
        self,
        repository_path: str,
        ref: Optional[str] = None,
        dry_run: bool = False,
    ):
        self.id = f"scan-{uuid.uuid4().hex[:12]}"
        self.status = ScanStatus.QUEUED
        self.repository_path = repository_path
        self.ref = ref
        self.dry_run = dry_run
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

    def update_status(self, status: ScanStatus, stage: Optional[str] = None):
        """Update scan status and timestamp."""
        self.status = status
        self.updated_at = datetime.now(timezone.utc).isoformat()
        if stage:
            self.current_stage = stage

    def set_stage(self, stage: str, status: str):
        """Track individual stage status."""
        self.stages[stage] = status
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def set_error(self, error: str):
        """Mark scan as failed with error message."""
        self.status = ScanStatus.FAILED
        self.error = error
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def load_output(self, agent: str, file_path: str):
        """Load agent JSON output from file."""
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
        """Convert to summary dict for API response."""
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
        }

    def to_detail(self) -> dict[str, Any]:
        """Convert to full detail dict for API response."""
        detail = self.to_summary()
        detail.update({
            "scanner_output": self.scanner_output,
            "analyzer_output": self.analyzer_output,
            "fixer_output": self.fixer_output,
            "risk_profile_output": self.risk_profile_output,
            "compliance_output": self.compliance_output,
            "stages": self.stages,
        })
        return detail


class ScanStore:
    """In-memory store for scan records."""

    def __init__(self):
        self._scans: dict[str, ScanRecord] = {}

    def create(
        self,
        repository_path: str,
        ref: Optional[str] = None,
        dry_run: bool = False,
    ) -> ScanRecord:
        """Create a new scan record."""
        scan = ScanRecord(repository_path, ref, dry_run)
        self._scans[scan.id] = scan
        return scan

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        """Get scan by ID."""
        return self._scans.get(scan_id)

    def list_all(self) -> list[ScanRecord]:
        """List all scans, newest first."""
        return sorted(
            self._scans.values(),
            key=lambda s: s.created_at,
            reverse=True,
        )

    def count(self) -> int:
        return len(self._scans)


# Global store instance
scan_store = ScanStore()
