"""
Models for continuous_pipeline_v0_1_0
Version: v0.1.0
Timestamp (UTC): 2026-04-14
"""

from dataclasses import dataclass


@dataclass
class CveCandidate:
    cve_id: str
    severity: str
    cvss_score: float
    published: str


@dataclass
class IntakePipelineSummary:
    total_fetched: int
    excluded_existing: int
    staged: int