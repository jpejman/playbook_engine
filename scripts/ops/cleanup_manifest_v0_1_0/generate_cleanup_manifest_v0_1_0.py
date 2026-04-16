"""
Generate cleanup manifest
Version: v0.1.0
Timestamp (UTC): 2026-04-16
"""

import json
from pathlib import Path

MANIFEST = {
    "priority_paths": {
        "priority_1_runtime": "scripts/prod/phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py",
        "priority_2_runtime": "scripts/prod/continuous_pipeline_v0_1_4/"
    },
    "shared_blockers": [
        {
            "path": "scripts/prod/phase1_direct_cve_runner.py",
            "status": "KEEP_ACTIVE",
            "reason": "Shared runner dependency for both runtime paths; currently blocked by generation CLI mismatch (--cve-id vs --cve)."
        },
        {
            "path": "scripts/prod/03_01_run_playbook_generation_v0_1_1_real_retrieval.py",
            "status": "KEEP_ACTIVE",
            "reason": "Generation subprocess invoked by direct runner; active runtime dependency."
        },
        {
            "path": "scripts/prod/02_85_build_context_snapshot_v0_1_0.py",
            "status": "KEEP_ACTIVE",
            "reason": "Context build step in active runtime path."
        }
    ],
    "keep_active_scripts": [
        {
            "path": "scripts/prod/phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py",
            "reason": "Priority #1 runtime path; must be restored to working order first."
        },
        {
            "path": "scripts/prod/phase1_selector_corrected.py",
            "reason": "Used by Priority #1 runtime path for OpenSearch + production filtering."
        },
        {
            "path": "scripts/prod/phase1_direct_cve_runner.py",
            "reason": "Shared pipeline executor for generation and QA steps."
        },
        {
            "path": "scripts/prod/continuous_pipeline_v0_1_4/",
            "reason": "Priority #2 modular queue-driven runtime path."
        }
    ],
    "keep_diagnostic_scripts": [
        {
            "path": "scripts/prod/continuous_pipeline_v0_1_4/diagnostics_v0_1_0/",
            "reason": "Current diagnostics package for queue/generation/QA tracing."
        },
        {
            "path": "scripts/prod/continuous_pipeline_v0_1_4/schema_audit_v0_1_0/",
            "reason": "Current schema/runtime audit package."
        }
    ],
    "keep_legacy_temp_scripts": [
        {
            "path": "scripts/prod/continuous_pipeline_v0_1_0/",
            "reason": "Still useful to understand intake/backfill design for Priority #2 path."
        },
        {
            "path": "scripts/prod/continuous_pipeline_v0_1_1/",
            "reason": "Historical queue worker evolution; keep until Priority #2 path is fully stabilized."
        },
        {
            "path": "scripts/prod/continuous_pipeline_v0_1_2/",
            "reason": "Historical processing bridge evolution; keep until Priority #2 path is fully stabilized."
        },
        {
            "path": "scripts/prod/continuous_pipeline_v0_1_3/",
            "reason": "Historical retry/failure evolution; keep until Priority #2 path is fully stabilized."
        }
    ],
    "archive_candidates": [
        {
            "path": "scripts/prod/phase1_continuous_execution_system_v0_2_0.py.archive",
            "reason": "Explicit archive file; not active runtime."
        },
        {
            "path": "scripts/prod/phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup copy.py",
            "reason": "Copy file; not authoritative runtime path."
        },
        {
            "path": "scripts/prod/phase1_selector_corrected copy.py",
            "reason": "Copy file; not authoritative runtime path."
        },
        {
            "path": "scripts/tools/verification/final_verification copy.py",
            "reason": "Copy file; verification helper only."
        }
    ],
    "delete_candidates_blocked": [
        {
            "path": "scripts/dev_diagnostics/",
            "reason": "Contains many likely obsolete files, but deletion is blocked until Priority #1 runtime is restored and dependency validation is complete."
        },
        {
            "path": "scripts/tools/",
            "reason": "Contains likely archive/delete candidates, but deletion is blocked until runtime and diagnostics manifests are validated."
        }
    ],
    "database_tables": [
        {
            "table": "playbook_engine.public.cve_queue",
            "status": "KEEP_ACTIVE",
            "reason": "Primary runtime queue; recently active."
        },
        {
            "table": "playbook_engine.public.cve_context_snapshot",
            "status": "KEEP_ACTIVE",
            "reason": "Still active though low-volume; context audit trail."
        },
        {
            "table": "playbook_engine.public.retrieval_runs",
            "status": "KEEP_ACTIVE",
            "reason": "Actively written by current runtime."
        },
        {
            "table": "playbook_engine.public.retrieval_documents",
            "status": "KEEP_ACTIVE",
            "reason": "Actively written by current runtime."
        },
        {
            "table": "playbook_engine.public.generation_runs",
            "status": "KEEP_ACTIVE",
            "reason": "Actively written by current runtime."
        },
        {
            "table": "playbook_engine.public.qa_runs",
            "status": "KEEP_ACTIVE",
            "reason": "Actively written by current runtime."
        },
        {
            "table": "playbook_engine.public.approved_playbooks",
            "status": "KEEP_LEGACY_TEMP",
            "reason": "Intended finalization table but currently degraded/inactive; missing expected cve_id in audit."
        },
        {
            "table": "playbook_engine.public.prompt_templates",
            "status": "KEEP_LEGACY_TEMP",
            "reason": "Control-plane table; not recently active but still configuration data."
        },
        {
            "table": "playbook_engine.public.prompt_template_versions",
            "status": "KEEP_LEGACY_TEMP",
            "reason": "Control-plane table; not recently active but still configuration data."
        },
        {
            "table": "playbook_engine.public.continuous_execution_locks",
            "status": "ARCHIVE_CANDIDATE",
            "reason": "No rows and no recent activity; appears unused by current runtime."
        },
        {
            "table": "vulnstrike.public.playbooks",
            "status": "KEEP_LEGACY_TEMP",
            "reason": "Legacy production reference table still used by production-guard checks."
        }
    ]
}

def main():
    base = Path(__file__).resolve().parent
    json_path = base / "cleanup_manifest_v0_1_0.json"
    md_path = base / "cleanup_manifest_v0_1_0.md"

    json_path.write_text(json.dumps(MANIFEST, indent=2), encoding="utf-8")

    md_lines = [
        "# Cleanup Manifest v0.1.0",
        "",
        "## Priority Runtime Paths",
        f"- Priority #1: `{MANIFEST['priority_paths']['priority_1_runtime']}`",
        f"- Priority #2: `{MANIFEST['priority_paths']['priority_2_runtime']}`",
        "",
        "## Shared Blockers",
    ]
    for item in MANIFEST["shared_blockers"]:
        md_lines.append(f"- `{item['path']}` — {item['status']} — {item['reason']}")
    md_lines.extend(["", "## Keep Active Scripts"])
    for item in MANIFEST["keep_active_scripts"]:
        md_lines.append(f"- `{item['path']}` — {item['reason']}")
    md_lines.extend(["", "## Keep Diagnostic Scripts"])
    for item in MANIFEST["keep_diagnostic_scripts"]:
        md_lines.append(f"- `{item['path']}` — {item['reason']}")
    md_lines.extend(["", "## Keep Legacy Temp Scripts"])
    for item in MANIFEST["keep_legacy_temp_scripts"]:
        md_lines.append(f"- `{item['path']}` — {item['reason']}")
    md_lines.extend(["", "## Archive Candidates"])
    for item in MANIFEST["archive_candidates"]:
        md_lines.append(f"- `{item['path']}` — {item['reason']}")
    md_lines.extend(["", "## Delete Candidates Blocked"])
    for item in MANIFEST["delete_candidates_blocked"]:
        md_lines.append(f"- `{item['path']}` — {item['reason']}")
    md_lines.extend(["", "## Database Tables"])
    for item in MANIFEST["database_tables"]:
        md_lines.append(f"- `{item['table']}` — {item['status']} — {item['reason']}")

    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(json.dumps({
        "json_manifest": str(json_path),
        "markdown_manifest": str(md_path),
        "priority_1_runtime": MANIFEST["priority_paths"]["priority_1_runtime"],
        "priority_2_runtime": MANIFEST["priority_paths"]["priority_2_runtime"]
    }, indent=2))

if __name__ == "__main__":
    main()