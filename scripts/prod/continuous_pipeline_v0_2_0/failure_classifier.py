"""
Failure classifier
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
"""

from __future__ import annotations

import re
from typing import Optional


class FailureClassifier:
    def classify(self, error_message: str, pipeline_status: Optional[str] = None, generation_status: Optional[str] = None) -> tuple[str, bool]:
        msg = (error_message or '').lower()
        pipeline_status = pipeline_status or ''
        generation_status = generation_status or ''

        # Stage-aware classification
        if 'already generated' in msg:
            return 'ALREADY_GENERATED', False
        if 'already in production' in msg:
            return 'ALREADY_IN_PRODUCTION', False
            
        # OpenSearch failures
        if any(pattern in msg for pattern in ['opensearch', 'nvd', 'elasticsearch', 'index']):
            if 'connection' in msg or 'connect' in msg or 'timeout' in msg:
                return 'OPENSEARCH_CONNECTION_ERROR', True
            if 'no document' in msg or 'no hits' in msg or 'not found' in msg:
                return 'OPENSEARCH_NO_DOCUMENT', False
            if 'index' in msg and ('missing' in msg or 'not exist' in msg or "doesn't exist" in msg):
                return 'OPENSEARCH_INDEX_MISSING', False
            return 'OPENSEARCH_ERROR', True
            
        # LLM failures
        if any(pattern in msg for pattern in ['ollama', 'llm', 'model', 'generate', 'response', 'completion']):
            if 'timeout' in msg:
                return 'LLM_TIMEOUT', True
            if 'connection' in msg or 'connect' in msg:
                return 'LLM_CONNECTION_ERROR', True
            return 'LLM_ERROR', True
            
        # Retrieval failures
        if 'retrieval' in msg:
            return 'RETRIEVAL_ERROR', True
            
        # Database/storage failures
        if any(pattern in msg for pattern in ['database', 'storage', 'psycopg2', 'postgres', 'insert', 'update', 'column', 'table']):
            if 'column' in msg and ('does not exist' in msg or 'missing' in msg):
                return 'STORAGE_COLUMN_MISMATCH', False
            if 'table' in msg and ('does not exist' in msg or 'missing' in msg):
                return 'STORAGE_TABLE_MISSING', False
            if 'insert' in msg or 'update' in msg:
                return 'STORAGE_WRITE_FAIL', False
            return 'STORAGE_FAIL', False
            
        # JSON parsing failures
        if 'json' in msg and ('decode' in msg or 'parse' in msg or 'invalid' in msg):
            return 'JSON_PARSE_ERROR', False
            
        # Missing required fields
        if 'missing' in msg and ('field' in msg or 'required' in msg):
            return 'MISSING_REQUIRED_FIELDS', False
            
        # Infrastructure failures
        if any(pattern in msg for pattern in ['timeout', 'connection', 'network', 'socket']):
            return 'INFRA_ERROR', True
            
        # Configuration errors
        if any(pattern in msg for pattern in ['config', 'configuration', 'env', 'environment']):
            return 'PIPELINE_CONFIG_ERROR', False
            
        # Default classification
        if pipeline_status == 'success' and generation_status == 'completed':
            return 'UNKNOWN_ERROR', True
        return 'UNKNOWN_ERROR', True
