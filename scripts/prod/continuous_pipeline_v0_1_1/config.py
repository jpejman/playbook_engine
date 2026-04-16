"""
Config for continuous_pipeline_v0_1_1
Version: v0.1.1
Timestamp (UTC): 2026-04-15
"""

class ContinuousPipelineWorkerConfig:
    QUEUE_TABLE = "public.cve_queue"

    STATUS_PENDING = "pending"
    STATUS_PROCESSING = "processing"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"

    DEFAULT_MAX_RUNS = 1
    DEFAULT_WAIT_SECONDS = 0