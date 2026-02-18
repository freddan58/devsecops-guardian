"""
DevSecOps Guardian - Azure Table Storage Persistence

Replaces the in-memory ScanStore with Azure Table Storage.
Same interface as the original ScanStore so no router changes needed.

Uses azure-data-tables SDK to persist scan records across container restarts.
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from azure.data.tables import TableServiceClient, TableClient
from azure.core.exceptions import ResourceNotFoundError

from schemas import ScanStatus


# Max property size in Azure Table Storage is 64KB for strings
# Agent outputs can be large, so we store them as JSON strings
MAX_PROPERTY_SIZE = 60_000  # Leave margin


def _truncate(data: Optional[dict], max_size: int = MAX_PROPERTY_SIZE) -> Optional[str]:
    """Serialize dict to JSON string, truncating if too large."""
    if data is None:
        return None
    s = json.dumps(data, ensure_ascii=False)
    if len(s) > max_size:
        # Store a marker that it was truncated + keep summary data
        summary = {
            "_truncated": True,
            "_original_size": len(s),
            "total_findings": data.get("total_findings"),
            "confirmed_count": data.get("confirmed_count"),
            "success_count": data.get("success_count"),
            "overall_risk_score": data.get("overall_risk_score"),
            "risk_level": data.get("risk_level"),
            "overall_risk_rating": data.get("overall_risk_rating"),
        }
        # Remove None values
        summary = {k: v for k, v in summary.items() if v is not None}
        return json.dumps(summary, ensure_ascii=False)
    return s


def _parse_json(s: Optional[str]) -> Optional[dict]:
    """Parse JSON string back to dict."""
    if s is None or s == "":
        return None
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return None


class ScanRecord:
    """Represents a single scan execution.

    Identical interface to the original in-memory version.
    """

    def __init__(
        self,
        repository_path: str,
        ref: Optional[str] = None,
        dry_run: bool = False,
        scan_id: Optional[str] = None,
    ):
        self.id = scan_id or f"scan-{uuid.uuid4().hex[:12]}"
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

        # Reference to store for auto-save
        self._store: Optional["TableScanStore"] = None

    def _auto_save(self):
        """Persist changes to Table Storage if store is attached."""
        if self._store:
            self._store.save(self)

    def update_status(self, status: ScanStatus, stage: Optional[str] = None):
        self.status = status
        self.updated_at = datetime.now(timezone.utc).isoformat()
        if stage:
            self.current_stage = stage
        self._auto_save()

    def set_stage(self, stage: str, status: str):
        self.stages[stage] = status
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self._auto_save()

    def set_error(self, error: str):
        self.status = ScanStatus.FAILED
        self.error = error
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self._auto_save()

    def load_output(self, agent: str, file_path: str):
        if not os.path.exists(file_path):
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            setattr(self, f"{agent}_output", data)
            self._auto_save()
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
        })
        return detail

    def to_entity(self) -> dict[str, Any]:
        """Convert to Azure Table Storage entity."""
        return {
            "PartitionKey": "scans",
            "RowKey": self.id,
            "status": self.status.value,
            "repository_path": self.repository_path,
            "ref": self.ref or "",
            "dry_run": self.dry_run,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "current_stage": self.current_stage or "",
            "error": self.error or "",
            "stages": json.dumps(self.stages),
            "scanner_output": _truncate(self.scanner_output),
            "analyzer_output": _truncate(self.analyzer_output),
            "fixer_output": _truncate(self.fixer_output),
            "risk_profile_output": _truncate(self.risk_profile_output),
            "compliance_output": _truncate(self.compliance_output),
        }

    @classmethod
    def from_entity(cls, entity: dict) -> "ScanRecord":
        """Reconstruct ScanRecord from Azure Table entity."""
        scan = cls(
            repository_path=entity.get("repository_path", ""),
            ref=entity.get("ref") or None,
            dry_run=entity.get("dry_run", False),
            scan_id=entity["RowKey"],
        )
        scan.status = ScanStatus(entity.get("status", "QUEUED"))
        scan.created_at = entity.get("created_at", scan.created_at)
        scan.updated_at = entity.get("updated_at", scan.updated_at)
        scan.current_stage = entity.get("current_stage") or None
        scan.error = entity.get("error") or None
        scan.stages = _parse_json(entity.get("stages")) or {}
        scan.scanner_output = _parse_json(entity.get("scanner_output"))
        scan.analyzer_output = _parse_json(entity.get("analyzer_output"))
        scan.fixer_output = _parse_json(entity.get("fixer_output"))
        scan.risk_profile_output = _parse_json(entity.get("risk_profile_output"))
        scan.compliance_output = _parse_json(entity.get("compliance_output"))
        return scan


class TableScanStore:
    """Azure Table Storage-backed scan store.

    Same interface as the original in-memory ScanStore.
    """

    def __init__(self, connection_string: str, table_name: str = "scans"):
        self._connection_string = connection_string
        self._table_name = table_name
        self._client: Optional[TableClient] = None
        self._init_client()

    def _init_client(self):
        """Initialize Table Storage client."""
        try:
            service = TableServiceClient.from_connection_string(self._connection_string)
            self._client = service.get_table_client(self._table_name)
            print(f"  [✓] Connected to Azure Table Storage: {self._table_name}")
        except Exception as e:
            print(f"  [!] Failed to connect to Table Storage: {e}")
            print(f"  [!] Falling back to in-memory store")
            self._client = None

    def _attach_store(self, scan: ScanRecord) -> ScanRecord:
        """Attach this store to a ScanRecord for auto-save."""
        scan._store = self
        return scan

    def save(self, scan: ScanRecord):
        """Persist a scan record to Table Storage."""
        if not self._client:
            return
        try:
            entity = scan.to_entity()
            self._client.upsert_entity(entity)
        except Exception as e:
            print(f"  [!] Failed to save scan {scan.id}: {e}")

    def create(
        self,
        repository_path: str,
        ref: Optional[str] = None,
        dry_run: bool = False,
    ) -> ScanRecord:
        """Create a new scan record and persist it."""
        scan = ScanRecord(repository_path, ref, dry_run)
        self._attach_store(scan)
        self.save(scan)
        return scan

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        """Get scan by ID from Table Storage."""
        if not self._client:
            return None
        try:
            entity = self._client.get_entity("scans", scan_id)
            scan = ScanRecord.from_entity(entity)
            self._attach_store(scan)
            return scan
        except ResourceNotFoundError:
            return None
        except Exception as e:
            print(f"  [!] Failed to get scan {scan_id}: {e}")
            return None

    def list_all(self) -> list[ScanRecord]:
        """List all scans, newest first."""
        if not self._client:
            return []
        try:
            entities = self._client.query_entities("PartitionKey eq 'scans'")
            scans = [ScanRecord.from_entity(e) for e in entities]
            scans.sort(key=lambda s: s.created_at, reverse=True)
            for s in scans:
                self._attach_store(s)
            return scans
        except Exception as e:
            print(f"  [!] Failed to list scans: {e}")
            return []

    def count(self) -> int:
        """Count total scans."""
        return len(self.list_all())
