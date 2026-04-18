"""
Failure classifier
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

import re
from typing import Optional


class FailureClassifier:
    DEAD_LETTER_FAILURES = {
        'SCHEMA_VALIDATION_FAIL',
        'OPENSEARCH_NO_DOCUMENT',
        'OPENSEARCH_INDEX_MISSING',
        'STORAGE_COLUMN_MISMATCH',
        'STORAGE_TABLE_MISSING',
        'STORAGE_WRITE_FAIL',
        'MISSING_REQUIRED_FIELDS',
        'PIPELINE_CONFIG_ERROR',
        'ALREADY_GENERATED',
        'ALREADY_IN_PRODUCTION',
    }
    
    def is_dead_letter(self, failure_type: str) -> bool:
        return failure_type in self.DEAD_LETTER_FAILURES
    
    def classify(self, error_message: str, pipeline_status: Optional[str] = None, generation_status: Optional[str] = None) -> tuple[str, bool]:
        msg = (error_message or '').lower()
        pipeline_status = pipeline_status or ''
        generation_status = generation_status or ''

        # Stage-aware classification
        if 'already generated' in msg:
            return 'ALREADY_GENERATED', False
        if 'already in production' in msg:
            return 'ALREADY_IN_PRODUCTION', False
            
        # JSON parsing failures - retryable since LLM might produce valid JSON on retry
        # Check this BEFORE LLM failures to catch JSON parse errors from LLM responses
        json_parse_patterns = [
            'failed to parse json',
            'expecting value',
            "expecting ',' delimiter", 
            'json decode',
            'json parse',
            'invalid json',
            'json.decoder.jsondecodeerror',
            'unexpected token',
            'extra data',
            'trailing comma',
            'malformed json'
        ]
        if 'json' in msg.lower():
            for pattern in json_parse_patterns:
                if pattern in msg.lower():
                    return 'JSON_PARSE_ERROR', True
            # General JSON error
            if any(term in msg.lower() for term in ['decode', 'parse', 'invalid', 'malformed']):
                return 'JSON_PARSE_ERROR', True
            
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
            
        # Schema validation failures (deterministic, non-retryable - dead_letter)
        if any(pattern in msg for pattern in ['schema', 'validation', 'canonical', 'header', 'workflows', 'pre_remediation_checks']):
            if 'missing' in msg or 'required' in msg or 'invalid' in msg or 'does not match' in msg:
                return 'SCHEMA_VALIDATION_FAIL', False
            
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
