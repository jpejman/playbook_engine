# Continuous Pipeline v0.1.0

## Purpose
Initial intake + staging pipeline for CVE processing.

## Responsibilities
- Pull CVEs from OpenSearch (NVD)
- Exclude CVEs already in production (vulnstrike.public.playbooks)
- Stage fresh CVEs into playbook_engine.cve_queue

## Non-Goals
- No generation
- No QA
- No promotion

## Run Command
python -m scripts.prod.continuous_pipeline_v0_1_0.intake_pipeline_v0_1_0

## Success Criteria
- No duplicate CVEs staged
- No CVEs staged that already exist in production
- Clean summary output