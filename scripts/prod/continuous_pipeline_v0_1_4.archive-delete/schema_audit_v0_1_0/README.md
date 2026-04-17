# Continuous Pipeline Schema Audit v0.1.0

## Purpose
Read-only audit tools for validating which tables and fields are active in the current pipeline.

## Run Command
python -m scripts.prod.continuous_pipeline_v0_1_4.schema_audit_v0_1_0.run_schema_runtime_audit_v0_1_0 --recent-limit 100

## Output
- Prints JSON summary to stdout
- Writes JSON report to logs/diagnostics/schema_runtime_audit_v0_1_0.json

## What It Audits
- table existence
- expected columns
- total row counts
- most recent timestamps
- whether the table appears active in the recent pipeline window
- runtime role annotation

## Notes
This package is read-only and does not modify data.