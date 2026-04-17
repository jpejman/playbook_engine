"""
Recent generation failure diagnostics
Version: v0.1.0
Timestamp (UTC): 2026-04-15
"""

import argparse
import json

from .diagnostics_db import PlaybookEngineDiagnosticsClient


def main():
    parser = argparse.ArgumentParser(description="Inspect recent generation failures and partial outcomes")
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()

    db = PlaybookEngineDiagnosticsClient()

    recent_generation_runs = db.fetch_all(
        """
        SELECT
            gr.id,
            gr.cve_id,
            gr.status AS generation_status,
            gr.model,
            gr.created_at,
            gr.generation_source,
            gr.retrieval_run_id,
            CASE
                WHEN gr.response IS NULL THEN 0
                ELSE LENGTH(gr.response)
            END AS response_length
        FROM public.generation_runs AS gr
        ORDER BY gr.id DESC
        LIMIT %s
        """,
        (args.limit,),
    )

    recent_queue_failures = db.fetch_all(
        """
        SELECT
            cq.id,
            cq.cve_id,
            cq.status,
            cq.retry_count,
            cq.failure_type,
            cq.last_error,
            cq.updated_at
        FROM public.cve_queue AS cq
        WHERE cq.status = 'failed'
        ORDER BY cq.updated_at DESC NULLS LAST
        LIMIT %s
        """,
        (args.limit,),
    )

    recent_qa_runs = db.fetch_all(
        """
        SELECT
            qr.id,
            qr.generation_run_id,
            qr.qa_result,
            qr.qa_score,
            qr.created_at
        FROM public.qa_runs AS qr
        ORDER BY qr.id DESC
        LIMIT %s
        """,
        (args.limit,),
    )

    payload = {
        "recent_generation_runs": [dict(r) for r in recent_generation_runs],
        "recent_queue_failures": [dict(r) for r in recent_queue_failures],
        "recent_qa_runs": [dict(r) for r in recent_qa_runs],
    }

    print(json.dumps(payload, indent=2, default=str))


if __name__ == "__main__":
    main()