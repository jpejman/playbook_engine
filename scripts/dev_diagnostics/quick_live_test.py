#!/usr/bin/env python3
"""
Quick test to capture live LLM output with minimal prompt.
"""

import os
import sys
import json
import time
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.llm_client import LLMClient


def test_live_llm():
    """Test live LLM with simple prompt."""
    print("Testing live LLM with simple prompt...")
    
    # Simple test prompt
    prompt = """Respond with valid JSON only: {"test": "success", "message": "API working"}"""
    
    llm = LLMClient()
    print(f"Model: {llm.model}")
    print(f"Base URL: {llm.base_url}")
    print(f"Prompt: {prompt[:100]}...")
    
    start_time = time.time()
    try:
        result = llm.generate(prompt)
        elapsed = time.time() - start_time
        
        print(f"\nResult:")
        print(f"  Status: {result.get('status')}")
        print(f"  Elapsed: {elapsed:.2f}s")
        print(f"  Raw response: {result.get('raw_text', '')[:200]}...")
        print(f"  Response length: {len(result.get('raw_text', ''))} chars")
        
        # Try to parse as JSON
        raw_text = result.get('raw_text', '')
        if raw_text:
            try:
                parsed = json.loads(raw_text.strip())
                print(f"  JSON parse: SUCCESS")
                print(f"  Parsed: {parsed}")
            except json.JSONDecodeError as e:
                print(f"  JSON parse: FAILED - {e}")
                print(f"  Raw text for analysis: {raw_text[:500]}")
        else:
            print("  No response text")
            
    except Exception as e:
        print(f"Error: {e}")
        elapsed = time.time() - start_time
        print(f"Elapsed: {elapsed:.2f}s")


if __name__ == "__main__":
    test_live_llm()