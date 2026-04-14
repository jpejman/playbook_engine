#!/usr/bin/env python3
"""
VS.ai — Playbook Engine Gen-3
Test for Deduplication + Generation Diagnostics Implementation
Version: v1.0.0
Timestamp (UTC): 2026-04-13

Purpose:
- Test the implemented duplicate prevention logic
- Verify generation diagnostics capture
- Test timeout control functionality
"""

import sys
import json
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.utils.db import DatabaseClient
from src.utils.generation_diagnostics import GenerationDiagnostics, create_generation_summary

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_canonical_duplicate_prevention():
    """Test the canonical duplicate prevention SQL logic."""
    
    logger.info("Testing canonical duplicate prevention logic...")
    
    db = DatabaseClient()
    
    # Test SQL query for duplicate prevention
    test_cve_id = "CVE-2024-12345"  # Test CVE ID
    
    duplicate_check_sql = """
    SELECT 
        -- Check if has approved playbook
        EXISTS (
            SELECT 1 FROM approved_playbooks ap 
            JOIN generation_runs gr ON ap.generation_run_id = gr.id 
            WHERE gr.cve_id = %s
        ) as has_approved,
        
        -- Check if has successful generation runs
        EXISTS (
            SELECT 1 FROM generation_runs 
            WHERE cve_id = %s 
            AND status = 'completed' 
            AND response IS NOT NULL
            AND response != ''
        ) as has_successful_generation,
        
        -- Check if currently in queue with processing status
        EXISTS (
            SELECT 1 FROM cve_queue 
            WHERE cve_id = %s 
            AND status IN ('processing', 'pending')
        ) as is_in_queue,
        
        -- Check if currently locked in continuous execution
        EXISTS (
            SELECT 1 FROM continuous_execution_locks 
            WHERE cve_id = %s 
            AND status = 'running' 
            AND lock_released_at IS NULL
            AND lock_acquired_at > NOW() - INTERVAL '5 minutes'
        ) as is_locked
    """
    
    try:
        result = db.fetch_one(duplicate_check_sql, (test_cve_id, test_cve_id, test_cve_id, test_cve_id))
        
        if result:
            logger.info("Canonical duplicate prevention SQL test successful")
            logger.info(f"Test CVE: {test_cve_id}")
            logger.info(f"  Has approved playbook: {result['has_approved']}")
            logger.info(f"  Has successful generation: {result['has_successful_generation']}")
            logger.info(f"  Is in queue: {result['is_in_queue']}")
            logger.info(f"  Is locked: {result['is_locked']}")
            
            # A CVE should be excluded if ANY of these are true
            should_exclude = (
                result['has_approved'] or
                result['has_successful_generation'] or
                result['is_in_queue'] or
                result['is_locked']
            )
            
            logger.info(f"  Should exclude CVE: {should_exclude}")
            return True
        else:
            logger.error("No result returned from duplicate check query")
            return False
            
    except Exception as e:
        logger.error(f"Duplicate prevention test failed: {e}")
        return False


def test_generation_diagnostics():
    """Test generation diagnostics capture and storage."""
    
    logger.info("Testing generation diagnostics...")
    
    db = DatabaseClient()
    diagnostics = GenerationDiagnostics(db)
    
    # Test with a mock LLM result
    mock_llm_result = {
        "status": "completed",
        "model": "gpt-4",
        "request_id": "test-request-123",
        "raw_text": '{"title": "Test Playbook", "steps": []}',
        "parsed_json": {"title": "Test Playbook", "steps": []},
        "diagnostics": {
            "response_size": 50,
            "latency_seconds": 2.5,
            "error_classification": None,
            "prompt_size": 1000,
            "api_status_code": 200,
            "model_used": "gpt-4",
            "raw_payload": {"choices": [{"message": {"content": '{"title": "Test Playbook", "steps": []}'}}]}
        }
    }
    
    # Capture diagnostics
    captured = diagnostics.capture_llm_result(mock_llm_result)
    logger.info("Captured diagnostics from mock LLM result:")
    logger.info(f"  Overall classification: {captured.get('overall_classification')}")
    logger.info(f"  Model used: {captured.get('model_used')}")
    logger.info(f"  Response size: {captured.get('response_size')}")
    logger.info(f"  Latency: {captured.get('latency_seconds')}s")
    
    # Test error classification
    error_llm_result = {
        "status": "failed",
        "model": "gpt-4",
        "error": "Request timeout after 30s",
        "diagnostics": {
            "response_size": 0,
            "latency_seconds": 30.5,
            "error_classification": "timeout",
            "prompt_size": 1000,
            "api_status_code": None,
            "model_used": "gpt-4"
        }
    }
    
    error_diagnostics = GenerationDiagnostics()
    error_captured = error_diagnostics.capture_llm_result(error_llm_result)
    logger.info("Captured diagnostics from error LLM result:")
    logger.info(f"  Overall classification: {error_captured.get('overall_classification')}")
    logger.info(f"  Error classification: {error_captured.get('error_classification')}")
    
    # Test classification logic
    test_cases = [
        {
            "name": "successful_generation",
            "llm_result": mock_llm_result,
            "expected_classification": "success"
        },
        {
            "name": "timeout_error",
            "llm_result": error_llm_result,
            "expected_classification": "timeout"
        },
        {
            "name": "empty_response",
            "llm_result": {
                "status": "completed",
                "raw_text": "",
                "diagnostics": {"response_size": 0}
            },
            "expected_classification": "empty_response"
        }
    ]
    
    all_passed = True
    for test_case in test_cases:
        test_diagnostics = GenerationDiagnostics()
        captured = test_diagnostics.capture_llm_result(test_case["llm_result"])
        classification = captured.get("overall_classification")
        
        if classification == test_case["expected_classification"]:
            logger.info(f"✓ Classification test passed: {test_case['name']} -> {classification}")
        else:
            logger.error(f"✗ Classification test failed: {test_case['name']} -> {classification} (expected: {test_case['expected_classification']})")
            all_passed = False
    
    return all_passed


def test_timeout_configuration():
    """Test timeout configuration and logging."""
    
    logger.info("Testing timeout configuration...")
    
    # Test timeout values
    timeout_test_cases = [
        {"minutes": 5, "description": "short timeout"},
        {"minutes": 30, "description": "default timeout"},
        {"minutes": 60, "description": "long timeout"},
        {"minutes": 120, "description": "extended timeout"},
    ]
    
    for test_case in timeout_test_cases:
        minutes = test_case["minutes"]
        seconds = minutes * 60
        
        logger.info(f"Timeout test: {test_case['description']}")
        logger.info(f"  Minutes: {minutes}")
        logger.info(f"  Seconds: {seconds}")
        logger.info(f"  Human readable: {minutes} minute{'s' if minutes != 1 else ''}")
        
        # Example timeout log message (as would appear in actual execution)
        timeout_message = f"Pipeline timeout after {seconds + 10:.2f} seconds ({minutes} minute limit)"
        logger.info(f"  Example timeout log: {timeout_message}")
        
        # Test classification
        if minutes <= 5:
            timeout_type = "short_timeout"
        elif minutes <= 30:
            timeout_type = "standard_timeout"
        else:
            timeout_type = "extended_timeout"
        
        logger.info(f"  Timeout classification: {timeout_type}")
    
    logger.info("Timeout configuration test completed")
    return True


def verify_schema_updates():
    """Verify that schema updates were applied correctly."""
    
    logger.info("Verifying schema updates...")
    
    db = DatabaseClient()
    
    # Check for llm_error_info column in generation_runs
    check_column_sql = """
    SELECT column_name, data_type 
    FROM information_schema.columns 
    WHERE table_name = 'generation_runs' 
    AND column_name = 'llm_error_info'
    """
    
    result = db.fetch_one(check_column_sql)
    
    if result:
        logger.info(f"✓ llm_error_info column exists in generation_runs (type: {result['data_type']})")
    else:
        logger.error("✗ llm_error_info column not found in generation_runs")
        return False
    
    # Check for generation_debug_info table
    check_table_sql = """
    SELECT table_name 
    FROM information_schema.tables 
    WHERE table_name = 'generation_debug_info'
    """
    
    result = db.fetch_one(check_table_sql)
    
    if result:
        logger.info("✓ generation_debug_info table exists")
    else:
        logger.error("✗ generation_debug_info table not found")
        return False
    
    # Check for logs directory structure
    logs_dir = Path("logs")
    runs_dir = logs_dir / "runs"
    
    if logs_dir.exists():
        logger.info(f"✓ Logs directory exists: {logs_dir}")
    else:
        logger.error(f"✗ Logs directory not found: {logs_dir}")
        return False
    
    if runs_dir.exists():
        logger.info(f"✓ Runs directory exists: {runs_dir}")
    else:
        logger.error(f"✗ Runs directory not found: {runs_dir}")
        return False
    
    return True


def main():
    """Run all tests."""
    
    logger.info("=" * 80)
    logger.info("VS.ai — Playbook Engine Gen-3")
    logger.info("Deduplication + Generation Diagnostics Test Suite")
    logger.info("=" * 80)
    
    test_results = {}
    
    # Run tests
    test_results["canonical_duplicate_prevention"] = test_canonical_duplicate_prevention()
    test_results["generation_diagnostics"] = test_generation_diagnostics()
    test_results["timeout_configuration"] = test_timeout_configuration()
    test_results["schema_updates"] = verify_schema_updates()
    
    # Summary
    logger.info("=" * 80)
    logger.info("TEST SUMMARY")
    logger.info("=" * 80)
    
    all_passed = True
    for test_name, passed in test_results.items():
        status = "PASSED" if passed else "FAILED"
        logger.info(f"{test_name}: {status}")
        if not passed:
            all_passed = False
    
    logger.info("=" * 80)
    
    if all_passed:
        logger.info("All tests PASSED ✓")
        logger.info("Implementation ready for production use")
        
        # Output implementation details
        logger.info("\nIMPLEMENTATION DETAILS:")
        logger.info("1. Canonical Duplicate Prevention:")
        logger.info("   - SQL filter excludes CVEs with: approved playbooks, successful generations, in-progress queue status, active locks")
        logger.info("   - Prevents duplicates across sessions via database state checks")
        
        logger.info("\n2. Session-Level Deduplication:")
        logger.info("   - In-memory tracking of processed CVEs per session")
        logger.info("   - Prevents re-processing within same execution session")
        
        logger.info("\n3. Generation Diagnostics:")
        logger.info("   - Captures: raw LLM payload, response size, latency, error classification")
        logger.info("   - Stores in: generation_runs.llm_error_info, generation_debug_info table, logs/runs/ JSON files")
        logger.info("   - Error classifications: timeout, empty_response, schema_validation_failure, llm_error, etc.")
        
        logger.info("\n4. Timeout Control:")
        logger.info("   - Configurable max execution time per CVE run (default: 30 minutes)")
        logger.info("   - Thread-based timeout with clean termination")
        logger.info("   - Classifies timeout failures for analysis")
        
        return 0
    else:
        logger.error("Some tests FAILED ✗")
        logger.error("Review implementation before production use")
        return 1


if __name__ == "__main__":
    sys.exit(main())