# Continuous Pipeline Diagnostics v0.1.0

## Purpose
Diagnostic scripts for the isolated continuous pipeline track.

## Scope
These scripts are read-only. They do not modify queue rows, generation runs, QA runs, or production playbooks.

## Primary Use Cases
- Inspect queue health and queue status distribution
- Inspect recent generation failures and pipeline outcomes
- Trace a single CVE across queue, context snapshots, generation runs, and QA runs
- Export a consolidated diagnostic JSON report for recent activity

## Run Commands

### Queue health
python -m scripts.prod.continuous_pipeline_v0_1_4.diagnostics_v0_1_0.inspect_queue_health_v0_1_0

### Recent generation failures
python -m scripts.prod.continuous_pipeline_v0_1_4.diagnostics_v0_1_0.inspect_generation_failures_v0_1_0 --limit 50

### Single CVE trace
python -m scripts.prod.continuous_pipeline_v0_1_4.diagnostics_v0_1_0.inspect_single_cve_trace_v0_1_0 --cve-id CVE-2025-12601

### Export consolidated diagnostics
python -m scripts.prod.continuous_pipeline_v0_1_4.diagnostics_v0_1_0.export_pipeline_diagnostics_v0_1_0 --limit 50

## Notes
- These scripts connect to playbook_engine and vulnstrike directly
- They are intended to replace manual SQL inspection during pipeline debugging