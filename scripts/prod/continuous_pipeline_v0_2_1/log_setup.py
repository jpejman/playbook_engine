"""
Logging setup for continuous_pipeline_v0_2_1
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path

from .config import ContinuousPipelineConfig


def setup_logging(name: str = "continuous_pipeline_v0_2_1") -> logging.Logger:
    """
    Set up file-based logging for v0.2.1.
    
    Creates logs directory if it doesn't exist and configures rotating file handler.
    """
    # Create logs directory if it doesn't exist
    log_file = ContinuousPipelineConfig.LOG_FILE
    log_dir = os.path.dirname(log_file)
    if log_dir:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Configure logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, ContinuousPipelineConfig.LOG_LEVEL))
    
    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Create rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_file,
        maxBytes=ContinuousPipelineConfig.LOG_MAX_BYTES,
        backupCount=ContinuousPipelineConfig.LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    
    # Create formatter
    formatter = logging.Formatter(ContinuousPipelineConfig.LOG_FORMAT)
    file_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(file_handler)
    
    # Also add console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger


def get_logger(name: str = "continuous_pipeline_v0_2_1") -> logging.Logger:
    """
    Get or create a logger with v0.2.1 configuration.
    
    If logging hasn't been set up yet, configures it automatically.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger = setup_logging(name)
    return logger