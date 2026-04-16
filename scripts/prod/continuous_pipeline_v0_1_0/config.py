"""
Config for continuous_pipeline_v0_1_0
Version: v0.1.0
Timestamp (UTC): 2026-04-14
"""

class ContinuousPipelineConfig:
    OPENSEARCH_INDEX = "cve"
    OPENSEARCH_FETCH_LIMIT = 100

    PLAYBOOK_ENGINE_DB = "playbook_engine"
    VULNSTRIKE_DB = "vulnstrike"

    QUEUE_TABLE = "cve_queue"

    MAX_STAGE_BATCH = 50