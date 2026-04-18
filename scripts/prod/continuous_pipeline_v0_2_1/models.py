"""
Models for continuous_pipeline_v0_2_0
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ClaimedQueueItem:
    id: int
    cve_id: str
    status: str
    created_at: Optional[str]
    updated_at: Optional[str]
    retry_count: int = 0


@dataclass
class WorkerProcessResult:
    cve_id: str
    success: bool
    skipped: bool = False
    error: Optional[str] = None
    failure_type: Optional[str] = None
    retryable: bool = False
    generation_run_id: Optional[int] = None
    context_snapshot_id: Optional[int] = None
    retrieval_run_id: Optional[int] = None
    pipeline_status: Optional[str] = None
    execution_status: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkerSummary:
    claimed: int
    completed: int
    failed: int
    skipped: int
    requeued: int


@dataclass
class QueueFillSummary:
    scanned: int
    enqueued: int
    skipped_existing_queue: int
    skipped_existing_generation: int
    skipped_in_production: int
    stopped_early: bool = False
