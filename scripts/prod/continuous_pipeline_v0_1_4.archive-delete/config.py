"""
Config for continuous_pipeline_v0_1_4
Version: v0.1.4
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
    DEFAULT_MAX_RETRIES = 2
    DEFAULT_BATCH_SIZE = 1
    DEFAULT_WORKERS = 1
    DEFAULT_MAX_CYCLES = None

    FAILURE_RETRYABLE = {
        "LLM_ERROR",
        "RETRIEVAL_ERROR",
        "INFRA_ERROR",
        "UNKNOWN_ERROR",
    }

    FAILURE_PERMANENT = {
        "QA_VALIDATION_FAIL",
        "STORAGE_FAIL",
        "ALREADY_IN_PRODUCTION",
    }

    MODE_SINGLE = "single"
    MODE_BATCH = "batch"
    MODE_PARALLEL = "parallel"
    MODE_LOOP = "loop"