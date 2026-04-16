"""
Models for continuous_pipeline_v0_1_1
Version: v0.1.1
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
    error: Optional[str] = None


@dataclass
class WorkerSummary:
    claimed: int
    completed: int
    failed: int