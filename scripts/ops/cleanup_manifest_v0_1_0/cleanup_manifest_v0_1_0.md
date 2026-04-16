# Cleanup Manifest v0.1.0

## Priority Runtime Paths
- Priority #1: `scripts/prod/phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py`
- Priority #2: `scripts/prod/continuous_pipeline_v0_1_4/`

## Shared Blockers
- `scripts/prod/phase1_direct_cve_runner.py` — KEEP_ACTIVE — Shared runner dependency for both runtime paths; currently blocked by generation CLI mismatch (--cve-id vs --cve).
- `scripts/prod/03_01_run_playbook_generation_v0_1_1_real_retrieval.py` — KEEP_ACTIVE — Generation subprocess invoked by direct runner; active runtime dependency.
- `scripts/prod/02_85_build_context_snapshot_v0_1_0.py` — KEEP_ACTIVE — Context build step in active runtime path.

## Keep Active Scripts
- `scripts/prod/phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py` — Priority #1 runtime path; must be restored to working order first.
- `scripts/prod/phase1_selector_corrected.py` — Used by Priority #1 runtime path for OpenSearch + production filtering.
- `scripts/prod/phase1_direct_cve_runner.py` — Shared pipeline executor for generation and QA steps.
- `scripts/prod/continuous_pipeline_v0_1_4/` — Priority #2 modular queue-driven runtime path.

## Keep Diagnostic Scripts
- `scripts/prod/continuous_pipeline_v0_1_4/diagnostics_v0_1_0/` — Current diagnostics package for queue/generation/QA tracing.
- `scripts/prod/continuous_pipeline_v0_1_4/schema_audit_v0_1_0/` — Current schema/runtime audit package.

## Keep Legacy Temp Scripts
- `scripts/prod/continuous_pipeline_v0_1_0/` — Still useful to understand intake/backfill design for Priority #2 path.
- `scripts/prod/continuous_pipeline_v0_1_1/` — Historical queue worker evolution; keep until Priority #2 path is fully stabilized.
- `scripts/prod/continuous_pipeline_v0_1_2/` — Historical processing bridge evolution; keep until Priority #2 path is fully stabilized.
- `scripts/prod/continuous_pipeline_v0_1_3/` — Historical retry/failure evolution; keep until Priority #2 path is fully stabilized.

## Archive Candidates
- `scripts/prod/phase1_continuous_execution_system_v0_2_0.py.archive` — Explicit archive file; not active runtime.
- `scripts/prod/phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup copy.py` — Copy file; not authoritative runtime path.
- `scripts/prod/phase1_selector_corrected copy.py` — Copy file; not authoritative runtime path.
- `scripts/tools/verification/final_verification copy.py` — Copy file; verification helper only.

## Delete Candidates Blocked
- `scripts/dev_diagnostics/` — Contains many likely obsolete files, but deletion is blocked until Priority #1 runtime is restored and dependency validation is complete.
- `scripts/tools/` — Contains likely archive/delete candidates, but deletion is blocked until runtime and diagnostics manifests are validated.

## Database Tables
- `playbook_engine.public.cve_queue` — KEEP_ACTIVE — Primary runtime queue; recently active.
- `playbook_engine.public.cve_context_snapshot` — KEEP_ACTIVE — Still active though low-volume; context audit trail.
- `playbook_engine.public.retrieval_runs` — KEEP_ACTIVE — Actively written by current runtime.
- `playbook_engine.public.retrieval_documents` — KEEP_ACTIVE — Actively written by current runtime.
- `playbook_engine.public.generation_runs` — KEEP_ACTIVE — Actively written by current runtime.
- `playbook_engine.public.qa_runs` — KEEP_ACTIVE — Actively written by current runtime.
- `playbook_engine.public.approved_playbooks` — KEEP_LEGACY_TEMP — Intended finalization table but currently degraded/inactive; missing expected cve_id in audit.
- `playbook_engine.public.prompt_templates` — KEEP_LEGACY_TEMP — Control-plane table; not recently active but still configuration data.
- `playbook_engine.public.prompt_template_versions` — KEEP_LEGACY_TEMP — Control-plane table; not recently active but still configuration data.
- `playbook_engine.public.continuous_execution_locks` — ARCHIVE_CANDIDATE — No rows and no recent activity; appears unused by current runtime.
- `vulnstrike.public.playbooks` — KEEP_LEGACY_TEMP — Legacy production reference table still used by production-guard checks.
