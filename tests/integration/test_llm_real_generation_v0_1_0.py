#!/usr/bin/env python3
"""
LLM Real Generation Connectivity Test
Version: v0.1.0
Timestamp: 2026-04-08

Purpose:
- Test real LLM API connectivity
- Send a small deterministic prompt
- Verify endpoint reachable
- Verify response received
- Verify model name captured
- Verify parser does not crash

Usage:
    python tests/integration/test_llm_real_generation_v0_1_0.py
"""

import os
import sys
import json
import logging
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent.parent.parent / '.env'
load_dotenv(env_path)

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.utils.llm_client import LLMClient

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_llm_real_generation():
    """Test real LLM generation with a small deterministic prompt."""
    
    logger.info("=" * 60)
    logger.info("LLM REAL GENERATION CONNECTIVITY TEST")
    logger.info("=" * 60)
    
    # Initialize client
    client = LLMClient()
    
    # Log configuration
    logger.info(f"LLM Configuration:")
    logger.info(f"  Base URL: {client.base_url}")
    logger.info(f"  Model: {client.model}")
    logger.info(f"  Timeout: {client.timeout_seconds}s")
    logger.info(f"  Generate Path: {client.generate_path}")
    logger.info(f"  API Key: {'[SET]' if client.api_key else '[NOT SET]'}")
    
    # Create small deterministic prompt
    test_prompt = """Please respond with a simple JSON object containing:
{
  "test_result": "success",
  "message": "LLM connectivity test passed",
  "timestamp": "2026-04-08T00:00:00Z"
}

Only return the JSON, no other text."""
    
    logger.info(f"Test prompt length: {len(test_prompt)} chars")
    logger.info(f"Test prompt preview: {test_prompt[:100]}...")
    
    # Call LLM
    logger.info("Calling LLM generate()...")
    result = client.generate(test_prompt)
    
    # Analyze result
    logger.info("\n" + "-" * 60)
    logger.info("TEST RESULTS")
    logger.info("-" * 60)
    
    # Check status
    status = result.get('status', 'unknown')
    logger.info(f"Status: {status}")
    
    if status == 'completed':
        logger.info("✓ LLM API call completed successfully")
        
        # Check model
        model = result.get('model', 'unknown')
        logger.info(f"Model: {model}")
        if model != 'unknown':
            logger.info("✓ Model name captured")
        else:
            logger.warning("⚠ Model name not captured")
        
        # Check raw text
        raw_text = result.get('raw_text', '')
        logger.info(f"Raw response length: {len(raw_text)} chars")
        if raw_text:
            logger.info("✓ Response received")
            logger.debug(f"Raw response (first 200 chars): {raw_text[:200]}")
        else:
            logger.error("✗ Empty response received")
            return False
        
        # Check parsed JSON
        parsed_json = result.get('parsed_json')
        if parsed_json:
            logger.info("✓ Response parsed as JSON")
            logger.debug(f"Parsed JSON: {json.dumps(parsed_json, indent=2)}")
            
            # Validate test JSON structure
            if isinstance(parsed_json, dict):
                if 'test_result' in parsed_json:
                    logger.info(f"✓ Test JSON contains expected key: 'test_result' = {parsed_json['test_result']}")
                else:
                    logger.warning("⚠ Test JSON missing expected key 'test_result'")
            else:
                logger.warning("⚠ Parsed JSON is not a dictionary")
        else:
            logger.info("ℹ Response not JSON (this is OK for some models)")
        
        # Check request ID
        request_id = result.get('request_id')
        if request_id:
            logger.info(f"Request ID: {request_id}")
            logger.info("✓ Request ID captured")
        else:
            logger.warning("⚠ Request ID not captured")
        
        logger.info("\n✓✓✓ LLM REAL GENERATION TEST PASSED ✓✓✓")
        return True
        
    else:
        # Failed status
        error = result.get('error', 'Unknown error')
        logger.error(f"✗ LLM API call failed: {error}")
        
        # Check if it's a connectivity issue vs. API error
        if "timeout" in error.lower() or "connection" in error.lower():
            logger.warning("⚠ This appears to be a connectivity/timeout issue")
            logger.warning("  Check network connectivity and LLM_BASE_URL configuration")
        elif "401" in error or "403" in error:
            logger.warning("⚠ This appears to be an authentication issue")
            logger.warning("  Check LLM_API_KEY configuration")
        
        logger.info("\n✗✗✗ LLM REAL GENERATION TEST FAILED ✗✗✗")
        return False


def main():
    """Main execution function."""
    try:
        success = test_llm_real_generation()
        if success:
            logger.info("\n" + "=" * 60)
            logger.info("ALL TESTS PASSED")
            logger.info("=" * 60)
            sys.exit(0)
        else:
            logger.error("\n" + "=" * 60)
            logger.error("TESTS FAILED")
            logger.error("=" * 60)
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Test execution failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()