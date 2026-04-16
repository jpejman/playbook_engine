# Continuous Pipeline v0.1.1

## Purpose
Initial queue worker for the isolated continuous pipeline track.

## Responsibilities
- Claim one CVE atomically from `playbook_engine.public.cve_queue`
- Mark it `processing`
- Run a minimal processing hook
- Mark it `completed` or `failed`

## Non-Goals
- No OpenSearch intake
- No production DB checks
- No generation
- No QA
- No promotion

## Run Command
python -m scripts.prod.continuous_pipeline_v0_1_1.queue_worker_v0_1_1

## Status Lifecycle
- `pending`
- `processing`
- `completed`
- `failed`

## Success Criteria
- Two concurrent workers do not claim the same row
- Correct status transitions
- Clean worker summary output