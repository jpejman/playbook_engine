"""
Config for continuous_pipeline_v0_2_0
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
"""

from __future__ import annotations

import os


class ContinuousPipelineConfig:
    QUEUE_TABLE = "public.cve_queue"
    STATUS_PENDING = "pending"
    STATUS_PROCESSING = "processing"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"

    DEFAULT_WAIT_SECONDS = int(os.getenv("CP_WAIT_SECONDS", "0"))
    DEFAULT_MAX_RETRIES = int(os.getenv("CP_MAX_RETRIES", "2"))
    DEFAULT_BATCH_SIZE = int(os.getenv("CP_BATCH_SIZE", "1"))
    DEFAULT_WORKERS = int(os.getenv("CP_WORKERS", "1"))
    DEFAULT_MAX_CYCLES = None
    DEFAULT_QUEUE_LOW_WATERMARK = int(os.getenv("CP_QUEUE_LOW_WATERMARK", "10"))
    DEFAULT_FEED_PAGE_SIZE = int(os.getenv("CP_FEED_PAGE_SIZE", "100"))
    DEFAULT_FEED_MAX_SCAN = int(os.getenv("CP_FEED_MAX_SCAN", "1000"))
    DEFAULT_FEED_TARGET = int(os.getenv("CP_FEED_TARGET", "100"))

    FAILURE_RETRYABLE = {
        "LLM_ERROR",
        "RETRIEVAL_ERROR",
        "INFRA_ERROR",
        "UNKNOWN_ERROR",
        "OPENSEARCH_ERROR",
    }

    FAILURE_PERMANENT = {
        "STORAGE_FAIL",
        "ALREADY_GENERATED",
        "ALREADY_IN_PRODUCTION",
        "PIPELINE_CONFIG_ERROR",
    }

    MODE_SINGLE = "single"
    MODE_BATCH = "batch"
    MODE_PARALLEL = "parallel"
    MODE_LOOP = "loop"

    OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://10.0.0.50:9200")
    OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX", "cve")
    OPENSEARCH_USERNAME = os.getenv("OPENSEARCH_USERNAME", "admin")
    OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")
    OPENSEARCH_VERIFY_TLS = os.getenv("OPENSEARCH_VERIFY_TLS", "false").lower() in {"1", "true", "yes"}

    LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:11434")
    LLM_GENERATE_PATH = os.getenv("LLM_GENERATE_PATH", "/api/generate")
    LLM_MODEL = os.getenv("LLM_MODEL", "gemma3:4b")
    LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "300"))

    DB_HOST = os.getenv("DB_HOST", "10.0.0.110")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_USER = os.getenv("DB_USER", "vulnstrike")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "vulnstrike")
