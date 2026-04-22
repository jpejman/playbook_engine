"""
Config for continuous_pipeline_v0_3_0 evaluation framework
Version: v0.3.0
Timestamp (UTC): 2026-04-18T23:12:39Z
"""

from __future__ import annotations

import os


class ContinuousPipelineConfig:
    QUEUE_TABLE = "public.cve_queue"
    STATUS_PENDING = "pending"
    STATUS_PROCESSING = "processing"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"
    STATUS_DEAD_LETTER = "dead_letter"

    DEFAULT_WAIT_SECONDS = int(os.getenv("CP_WAIT_SECONDS", "0"))
    DEFAULT_MAX_RETRIES = int(os.getenv("CP_MAX_RETRIES", "2"))
    DEFAULT_BATCH_SIZE = int(os.getenv("CP_BATCH_SIZE", "1"))
    DEFAULT_WORKERS = int(os.getenv("CP_WORKERS", "1"))
    DEFAULT_MAX_CYCLES = None
    DEFAULT_QUEUE_LOW_WATERMARK = int(os.getenv("CP_QUEUE_LOW_WATERMARK", "10"))
    DEFAULT_FEED_PAGE_SIZE = int(os.getenv("CP_FEED_PAGE_SIZE", "100"))
    DEFAULT_FEED_MAX_SCAN = int(os.getenv("CP_FEED_MAX_SCAN", "1000"))
    DEFAULT_FEED_TARGET = int(os.getenv("CP_FEED_TARGET", "100"))
    DEFAULT_FEED_MAX_SCAN_WINDOWS = int(os.getenv("CP_FEED_MAX_SCAN_WINDOWS", "10"))
    DEFAULT_FEED_MAX_TOTAL_SCAN = int(os.getenv("CP_FEED_MAX_TOTAL_SCAN", "5000"))
    DEFAULT_FEED_MIN_ENQUEUE_REQUIRED = int(os.getenv("CP_FEED_MIN_ENQUEUE_REQUIRED", "5"))
    
    LOG_FILE = os.getenv("CP_LOG_FILE", "logs/continuous_pipeline_v0_3_0.log")
    LOG_LEVEL = os.getenv("CP_LOG_LEVEL", "INFO")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5

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

    CP_FEED_USE_PERSISTENT_CURSOR = os.getenv("CP_FEED_USE_PERSISTENT_CURSOR", "false").lower() == "true"
    CP_FEED_CURSOR_FEEDER_NAME = os.getenv("CP_FEED_CURSOR_FEEDER_NAME", "default_nvd_feeder")
    CP_FEED_CURSOR_PAGE_SIZE = int(os.getenv("CP_FEED_CURSOR_PAGE_SIZE", "100"))

    #LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:11434")
    #LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://10.0.0.100:11434")
    LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://10.0.0.202:11434")
    LLM_GENERATE_PATH = os.getenv("LLM_GENERATE_PATH", "/api/generate")

    # ============================================================
    # LLM MODEL CONFIGURATION
    # Keep candidate models here for quick testing and output review.
    # Only one active default should be used at a time.
    # Environment variable LLM_MODEL overrides DEFAULT_LLM_MODEL.
    # ============================================================

    # LLM_MODEL = "DeepSeek-Coder-V2"
    # LLM_MODEL = "DeepSeek-R1"
    # LLM_MODEL = "gemma3:4b"
    # LLM_MODEL = "gemma4:e4b"
    # LLM_MODEL = "glm-5:cloud"
    # LLM_MODEL = "kimi-k2.5:cloud"
    # LLM_MODEL = "llama3.1:8b"
    # LLM_MODEL = "llama3.2"
    # LLM_MODEL = "qwen2.5"
    # LLM_MODEL = "qwen2.5:14b"  test
    # LLM_MODEL = "qwen2.5-Coder"
    # LLM_MODEL = "qwen2.5-coder:14b" test
    # LLM_MODEL = "qwen2.5-coder:14b"
    # LLM_MODEL = "qwen3:8b" test
    # LLM_MODEL = "qwen3.5:4b"
    # LLM_MODEL = "qwen3.5:9b"
    
    DEFAULT_LLM_MODEL = "qwen2.5-coder:14b"
    LLM_MODEL = os.getenv("LLM_MODEL", DEFAULT_LLM_MODEL)
    #LLM_MODEL = os.getenv("LLM_MODEL", "gemma3:4b")

    LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "300"))

    #POSTGRES DB 
    DB_HOST = os.getenv("DB_HOST", "10.0.0.110")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_USER = os.getenv("DB_USER", "vulnstrike")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "vulnstrike")