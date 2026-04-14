# LLM Connectivity Test
# Version: v0.1.2
# Timestamp: 2026-04-07

"""
Integration test for LLM connectivity.
Tests the LLM client initialization and configuration.
"""

import os
import sys
import logging
from pathlib import Path
from unittest.mock import Mock, patch
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent.parent.parent / '.env'
load_dotenv(env_path)

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from src.utils.llm_client import LLMClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_llm_client_initialization():
    """Test LLM client initialization."""
    client = LLMClient()
    
    assert client.api_key == os.getenv('LLM_API_KEY', '')
    assert client.model == os.getenv('LLM_MODEL', 'gpt-4')
    assert client.base_url == os.getenv('LLM_BASE_URL', 'https://api.openai.com/v1')
    assert client.temperature == float(os.getenv('LLM_TEMPERATURE', '0.7'))
    assert client.max_tokens == int(os.getenv('LLM_MAX_TOKENS', '2000'))
    
    logger.info("LLM client initialization test passed")


def test_llm_generate_real():
    """Test LLM generate method (real implementation)."""
    client = LLMClient()
    
    # Test that generate method returns a dict with expected structure
    result = client.generate("Test prompt")
    
    # Check result structure
    assert isinstance(result, dict), "Result should be a dictionary"
    assert "model" in result, "Result should contain 'model' key"
    assert "raw_text" in result, "Result should contain 'raw_text' key"
    assert "parsed_json" in result, "Result should contain 'parsed_json' key"
    assert "request_id" in result, "Result should contain 'request_id' key"
    assert "status" in result, "Result should contain 'status' key"
    
    # Status should be either "completed" or "failed"
    assert result["status"] in ["completed", "failed"], "Status should be 'completed' or 'failed'"
    
    logger.info("LLM generate real implementation test passed")


def test_llm_evaluate_real():
    """Test LLM evaluate method (real implementation)."""
    client = LLMClient()
    
    # Test that evaluate method returns a dict with expected structure
    result = client.evaluate("Test text to evaluate")
    
    # Check result structure
    assert isinstance(result, dict), "Result should be a dictionary"
    assert "model" in result, "Result should contain 'model' key"
    assert "raw_text" in result, "Result should contain 'raw_text' key"
    assert "parsed_json" in result, "Result should contain 'parsed_json' key"
    assert "request_id" in result, "Result should contain 'request_id' key"
    assert "status" in result, "Result should contain 'status' key"
    
    # Status should be either "completed" or "failed"
    assert result["status"] in ["completed", "failed"], "Status should be 'completed' or 'failed'"
    
    logger.info("LLM evaluate real implementation test passed")


def test_llm_chat_real():
    """Test LLM chat method (real implementation)."""
    client = LLMClient()
    
    # Test that chat method returns a dict with expected structure
    messages = [{"role": "user", "content": "Hello, this is a test message."}]
    result = client.chat(messages)
    
    # Check result structure
    assert isinstance(result, dict), "Result should be a dictionary"
    assert "model" in result, "Result should contain 'model' key"
    assert "raw_text" in result, "Result should contain 'raw_text' key"
    assert "parsed_json" in result, "Result should contain 'parsed_json' key"
    assert "request_id" in result, "Result should contain 'request_id' key"
    assert "status" in result, "Result should contain 'status' key"
    
    # Status should be either "completed" or "failed"
    assert result["status"] in ["completed", "failed"], "Status should be 'completed' or 'failed'"
    
    logger.info("LLM chat real implementation test passed")


if __name__ == "__main__":
    """Run LLM connectivity tests."""
    print("Running LLM connectivity tests...")
    
    try:
        test_llm_client_initialization()
        test_llm_generate_real()
        test_llm_evaluate_real()
        test_llm_chat_real()
        
        print("All LLM connectivity tests passed!")
    except Exception as e:
        print(f"LLM connectivity tests failed: {e}")
        sys.exit(1)