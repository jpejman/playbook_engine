"""
Single CVE trace diagnostics
Version: v0.1.0
Timestamp (UTC): 2026-04-15
"""

import argparse
import json

from .diagnostics_db import PlaybookEngineDiagnosticsClient, VulnstrikeDiagnosticsClient


def main():
    parser = argparse.ArgumentParser(description="Trace one CVE across queue, generation, QA, and production")
    parser.add_argument("--cve-id", required=True)
    args = parser.parse_args()

    cve_id = args.cve_id

    pe = PlaybookEngineDiagnosticsClient()
    prod = VulnstrikeDiagnosticsClient()

    queue_rows = pe.fetch_all(
        """
        SELECT *
        FROM public.cve_queue
        WHERE cve_id = %s
        ORDER BY updated_at DESC NULLS LAST, created_at DESC
        """,
        (cve_id,),
    )

    context_rows = pe.fetch_all(
        """
        SELECT *
        FROM public.cve_context_snapshot
        WHERE cve_id = %s
        ORDER BY id DESC
        """,
        (cve_id,),
    )

    generation_rows = pe.fetch_all(
        """
        SELECT *
        FROM public.generation_runs
        WHERE cve_id = %s
        ORDER BY id DESC
        """,
        (cve_id,),
    )

    qa_rows = pe.fetch_all(
        """
        SELECT qr.*
        FROM public.qa_runs AS qr
        JOIN public.generation_runs AS gr
          ON qr.generation_run_id = gr.id
        WHERE gr.cve_id = %s
        ORDER BY qr.id DESC
        """,
        (cve_id,),
    )

    production_rows = prod.fetch_all(
        """
        SELECT id, cve_id, created_at, updated_at
        FROM public.playbooks
        WHERE cve_id = %s
        ORDER BY updated_at DESC NULLS LAST, created_at DESC
        """,
        (cve_id,),
    )

    payload = {
        "cve_id": cve_id,
        "queue_rows": [dict(r) for r in queue_rows],
        "context_rows": [dict(r) for r in context_rows],
        "generation_rows": [dict(r) for r in generation_rows],
        "qa_rows": [dict(r) for r in qa_rows],
        "production_rows": [dict(r) for r in production_rows],
    }

    print(json.dumps(payload, indent=2, default=str))


if __name__ == "__main__":
    main()