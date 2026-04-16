"""
Consolidated pipeline diagnostics exporter
Version: v0.1.0
Timestamp (UTC): 2026-04-15
"""

import argparse
import json
from pathlib import Path

from .diagnostics_db import PlaybookEngineDiagnosticsClient, VulnstrikeDiagnosticsClient


def main():
    parser = argparse.ArgumentParser(description="Export consolidated diagnostics for recent queue and generation activity")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--out", default="logs/diagnostics/continuous_pipeline_diagnostics_v0_1_0.json")
    args = parser.parse_args()

    pe = PlaybookEngineDiagnosticsClient()
    prod = VulnstrikeDiagnosticsClient()

    queue_recent = pe.fetch_all(
        """
        SELECT id, cve_id, status, priority, retry_count, failure_type, last_error, created_at, updated_at
        FROM public.cve_queue
        ORDER BY updated_at DESC NULLS LAST, created_at DESC
        LIMIT %s
        """,
        (args.limit,),
    )

    generation_recent = pe.fetch_all(
        """
        SELECT id, cve_id, status, model, generation_source, retrieval_run_id, created_at
        FROM public.generation_runs
        ORDER BY id DESC
        LIMIT %s
        """,
        (args.limit,),
    )

    qa_recent = pe.fetch_all(
        """
        SELECT id, generation_run_id, qa_result, qa_score, created_at
        FROM public.qa_runs
        ORDER BY id DESC
        LIMIT %s
        """,
        (args.limit,),
    )

    production_recent = prod.fetch_all(
        """
        SELECT id, cve_id, created_at, updated_at
        FROM public.playbooks
        ORDER BY updated_at DESC NULLS LAST, created_at DESC
        LIMIT %s
        """,
        (args.limit,),
    )

    payload = {
        "queue_recent": [dict(r) for r in queue_recent],
        "generation_recent": [dict(r) for r in generation_recent],
        "qa_recent": [dict(r) for r in qa_recent],
        "production_recent": [dict(r) for r in production_recent],
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    print(json.dumps({
        "output_file": str(out_path),
        "queue_rows": len(payload["queue_recent"]),
        "generation_rows": len(payload["generation_recent"]),
        "qa_rows": len(payload["qa_recent"]),
        "production_rows": len(payload["production_recent"]),
    }, indent=2))


if __name__ == "__main__":
    main()