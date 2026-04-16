"""
Worker processing stub
Version: v0.1.1
Timestamp (UTC): 2026-04-15
"""

import time

from .models import WorkerProcessResult


class WorkerProcessor:
    """
    Minimal processing stub for v0.1.1.

    This does not call generation yet.
    It only simulates successful processing.
    """

    def process(self, cve_id: str) -> WorkerProcessResult:
        try:
            # Minimal stub work so queue mechanics can be validated first.
            time.sleep(0.25)
            return WorkerProcessResult(cve_id=cve_id, success=True, error=None)
        except Exception as e:
            return WorkerProcessResult(cve_id=cve_id, success=False, error=str(e))