#!/usr/bin/env python3
"""
Verify LLM API calls and responses are working
"""

import os
import sys
import json
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

print('=== LLM Configuration Verification ===')
print(f'LLM_MODEL: {os.getenv("LLM_MODEL")}')
print(f'LLM_BASE_URL: {os.getenv("LLM_BASE_URL")}')
print(f'LLM_GENERATE_PATH: {os.getenv("LLM_GENERATE_PATH")}')
print(f'LLM_TIMEOUT_SECONDS: {os.getenv("LLM_TIMEOUT_SECONDS")}')
print(f'LLM_API_KEY: {"[SET]" if os.getenv("LLM_API_KEY") else "[NOT SET]"}')
print()

# Test LLM client
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.utils.llm_client import LLMClient

client = LLMClient()
print('=== LLM Client Initialization ===')
print(f'Model: {client.model}')
print(f'Base URL: {client.base_url}')
print(f'Generate Path: {client.generate_path}')
print(f'Timeout: {client.timeout_seconds}s')
print()

# Test simple generation
print('=== Simple Generation Test ===')
test_prompt = 'Respond with: {"test": "success", "message": "API working"}'
print(f'Test prompt: {test_prompt[:50]}...')
result = client.generate(test_prompt)
print(f'Status: {result["status"]}')
print(f'Model: {result["model"]}')
print(f'Response length: {len(result.get("raw_text", ""))} chars')
print(f'Parsed JSON: {"Yes" if result.get("parsed_json") else "No"}')
print(f'Error: {result.get("error", "None")}')
print()

if result["status"] == "completed":
    print('✅ API calls are working correctly')
    if result.get("parsed_json"):
        print('✅ JSON parsing is working')
    else:
        print('⚠ Response not JSON (may need prompt tuning)')
else:
    print('❌ API calls failed')

# Test with a more complex prompt
print('\n=== Complex Prompt Test ===')
complex_prompt = """You are a cybersecurity playbook generator. Create a simple playbook for testing.

Output in JSON format:
{
  "playbook": {
    "title": "Test Playbook",
    "cve_id": "CVE-TEST-0001",
    "remediation_steps": [
      {
        "step_number": 1,
        "description": "Test step"
      }
    ]
  }
}"""
print(f'Complex prompt length: {len(complex_prompt)} chars')
complex_result = client.generate(complex_prompt)
print(f'Status: {complex_result["status"]}')
print(f'Response length: {len(complex_result.get("raw_text", ""))} chars')
print(f'Parsed JSON: {"Yes" if complex_result.get("parsed_json") else "No"}')

if complex_result["status"] == "completed":
    print('✅ Complex API calls working')
else:
    print('❌ Complex API calls failed')