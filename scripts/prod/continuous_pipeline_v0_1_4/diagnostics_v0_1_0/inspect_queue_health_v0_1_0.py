"""
Queue health diagnostics
Version: v0.1.0
Timestamp (UTC): 2026-04-15
"""

import json

from .diagnostics_db import PlaybookEngineDiagnosticsClient


def main():
    db = PlaybookEngineDiagnosticsClient()

    status_counts = db.fetch_all(
        """
        SELECT status, COUNT(*) AS row_count
        FROM public.cve_queue
        GROUP BY status
        ORDER BY status
        """
    )

    retry_distribution = db.fetch_all(
        """
        SELECT COALESCE(retry_count, 0) AS retry_count, COUNT(*) AS row_count
        FROM public.cve_queue
        GROUP BY COALESCE(retry_count, 0)
        ORDER BY retry_count
        """
    )

    failure_type_counts = db.fetch_all(
        """
        SELECT COALESCE(failure_type, 'NULL') AS failure_type, COUNT(*) AS row_count
        FROM public.cve_queue
        GROUP BY COALESCE(failure_type, 'NULL')
        ORDER BY row_count DESC, failure_type
        """
    )

    duplicate_cves = db.fetch_all(
        """
        SELECT cve_id, COUNT(*) AS row_count
        FROM public.cve_queue
        GROUP BY cve_id
        HAVING COUNT(*) > 1
        ORDER BY row_count DESC, cve_id
        """
    )

    recent_rows = db.fetch_all(
        """
        SELECT id, cve_id, status, priority, retry_count, failure_type, created_at, updated_at
        FROM public.cve_queue
        ORDER BY updated_at DESC NULLS LAST, created_at DESC
        LIMIT 25
        """
    )

    summary = {
        "status_counts": [dict(r) for r in status_counts],
        "retry_distribution": [dict(r) for r in retry_distribution],
        "failure_type_counts": [dict(r) for r in failure_type_counts],
        "duplicate_cve_count": len(duplicate_cves),
        "duplicates": [dict(r) for r in duplicate_cves[:50]],
        "recent_rows": [dict(r) for r in recent_rows],
    }

    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()