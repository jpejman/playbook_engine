# Cleanup Manifest v0.1.0

## Purpose
Create a read-only manifest of scripts and database tables that are:
- required for running playbooks
- required for diagnostics
- temporary legacy dependencies
- likely archive candidates
- possible future delete candidates

## Priority Order
1. `scripts/prod/phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py`
2. `scripts/prod/continuous_pipeline_v0_1_4/`

## Rules
- Do not delete anything
- Do not move anything
- Do not change database schema
- Only generate classification artifacts

## Output
- `cleanup_manifest_v0_1_0.md`
- `cleanup_manifest_v0_1_0.json`