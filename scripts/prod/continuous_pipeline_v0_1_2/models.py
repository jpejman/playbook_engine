"""
Models for continuous_pipeline_v0_1_2
Version: v0.1.2
Timestamp (UTC): 2026-04-15
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ClaimedQueueItem:
    id: int
    cve_id: str
    status: str
    created_at: Optional[str]
    updated_at: Optional[str]


@dataclass
class WorkerProcessResult:
    cve_id: str
    success: bool
    skipped: bool = False
    error: Optional[str] = None
    generation_run_id: Optional[int] = None
    context_snapshot_id: Optional[int] = None
    qa_result: Optional[str] = None
    qa_score: Optional[float] = None
    pipeline_status: Optional[str] = None


@dataclass
class WorkerSummary:
    claimed: int
    completed: int
    failed: int
    skipped: int