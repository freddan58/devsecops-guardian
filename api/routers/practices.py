"""
DevSecOps Guardian - Best Practices Router

Aggregates best_practices_analysis from all findings into a maturity score.
"""

from fastapi import APIRouter, HTTPException
from typing import Any

from models import scan_store
from schemas import PracticesSummary

router = APIRouter(prefix="/api/scans", tags=["practices"])


def _compute_maturity_score(
    total_violations: int,
    total_followed: int,
) -> int:
    """Compute security maturity score 0-100."""
    total = total_violations + total_followed
    if total == 0:
        return 50  # No data = neutral
    return max(0, min(100, round((total_followed / total) * 100)))


@router.get("/{scan_id}/practices", response_model=PracticesSummary)
async def get_practices(scan_id: str):
    """Get aggregated best practices analysis for a scan."""
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    if not scan.analyzer_output:
        raise HTTPException(
            status_code=400,
            detail="Analyzer has not completed yet"
        )

    all_violations: list[dict] = []
    all_followed: list[dict] = []
    category_stats: dict[str, dict[str, int]] = {}

    for f in scan.analyzer_output.get("findings", []):
        bp = f.get("best_practices_analysis", {})
        if not isinstance(bp, dict):
            continue

        for v in bp.get("violated_practices", []):
            if isinstance(v, dict):
                all_violations.append(v)
                cat = v.get("category", "Other")
                if cat not in category_stats:
                    category_stats[cat] = {"violations": 0, "followed": 0}
                category_stats[cat]["violations"] += 1

        for fp in bp.get("followed_practices", []):
            if isinstance(fp, dict):
                all_followed.append(fp)
                cat = fp.get("category", "Other")
                if cat not in category_stats:
                    category_stats[cat] = {"violations": 0, "followed": 0}
                category_stats[cat]["followed"] += 1

    # Deduplicate violations by (practice, category)
    seen_violations: set[tuple] = set()
    unique_violations = []
    for v in all_violations:
        key = (v.get("practice", ""), v.get("category", ""))
        if key not in seen_violations:
            seen_violations.add(key)
            unique_violations.append(v)

    # Deduplicate followed
    seen_followed: set[tuple] = set()
    unique_followed = []
    for fp in all_followed:
        key = (fp.get("practice", ""), fp.get("category", ""))
        if key not in seen_followed:
            seen_followed.add(key)
            unique_followed.append(fp)

    # Anti-patterns: violations that appear 2+ times
    violation_counts: dict[str, int] = {}
    for v in all_violations:
        name = v.get("practice", "Unknown")
        violation_counts[name] = violation_counts.get(name, 0) + 1

    anti_patterns = [
        {
            "practice": name,
            "occurrences": count,
            "category": next(
                (v.get("category", "Other") for v in all_violations if v.get("practice") == name),
                "Other",
            ),
        }
        for name, count in sorted(violation_counts.items(), key=lambda x: -x[1])
        if count >= 2
    ]

    maturity = _compute_maturity_score(len(all_violations), len(all_followed))

    return PracticesSummary(
        scan_id=scan_id,
        total_violations=len(all_violations),
        total_followed=len(all_followed),
        maturity_score=maturity,
        categories=category_stats,
        top_violations=unique_violations[:10],
        top_followed=unique_followed[:10],
        anti_patterns=anti_patterns,
    )
