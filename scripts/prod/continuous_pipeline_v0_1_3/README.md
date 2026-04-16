# Continuous Pipeline v0.1.3

## Purpose
Isolated retry- and failure-aware queue worker for the continuous pipeline track.

## Responsibilities
- Claim one CVE atomically from `playbook_engine.public.cve_queue`
- Re-check whether the CVE already exists in `vulnstrike.public.playbooks`
- Run the existing direct-CVE processing path for the claimed CVE
- Classify failures
- Retry eligible failures up to a configured max
- Mark permanent failures as `failed`

## Non-Goals
- No OpenSearch intake
- No mutation of original Gen-3 code
- No new QA redesign
- No new promotion redesign

## Run Command
python -m scripts.prod.continuous_pipeline_v0_1_3.queue_worker_v0_1_3

## Status Lifecycle
- `pending`
- `processing`
- `completed`
- `failed`

## Success Criteria
- Two concurrent workers do not claim the same row
- Worker produces a real processing result
- Retryable failures are re-queued
- Permanent failures are marked failed
- Clean worker summary output