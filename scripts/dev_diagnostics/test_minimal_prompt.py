#!/usr/bin/env python3
"""
Test minimal prompt to capture failure modes.
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


def test_minimal_prompt():
    """Test with minimal prompt to see raw output."""
    print("Testing minimal prompt with gemma3:4b...")
    
    # Minimal test prompt
    prompt = """Generate a remediation playbook for CVE-2023-4863 affecting Google WebP.
Output must be valid JSON with these exact keys: title, cve_id, vendor, product, severity, workflows.
Workflows must be a list with at least one workflow containing steps.
Do not include any other text, only JSON."""

    llm = LLMClient()
    print(f"Model: {llm.model}")
    print(f"Base URL: {llm.base_url}")
    print(f"Timeout: {llm.timeout_seconds}s")
    print(f"\nPrompt:\n{prompt}")
    print("\n" + "="*60)
    
    start_time = time.time()
    try:
        result = llm.generate(prompt)
        elapsed = time.time() - start_time
        
        print(f"\nResult after {elapsed:.1f}s:")
        print(f"Status: {result.get('status')}")
        
        raw_text = result.get('raw_text', '')
        print(f"Response length: {len(raw_text)} chars")
        
        if raw_text:
            print(f"\nRaw response (first 1000 chars):")
            print("-" * 60)
            print(raw_text[:1000])
            if len(raw_text) > 1000:
                print("...")
            print("-" * 60)
            
            # Try to parse
            try:
                parsed = json.loads(raw_text.strip())
                print("\nJSON parse: SUCCESS")
                print(f"Top-level keys: {list(parsed.keys())}")
                
                # Check for specific keys
                if 'workflows' in parsed:
                    print(f"Has 'workflows': YES")
                    if isinstance(parsed['workflows'], list):
                        print(f"  workflows is list with {len(parsed['workflows'])} items")
                else:
                    print(f"Has 'workflows': NO")
                    
                if 'remediation_steps' in parsed:
                    print(f"Has 'remediation_steps': YES (LEGACY)")
                    
            except json.JSONDecodeError as e:
                print(f"\nJSON parse: FAILED - {e}")
                # Try to clean markdown
                clean = raw_text.strip()
                if clean.startswith('```json'):
                    clean = clean[7:]
                if clean.startswith('```'):
                    clean = clean[3:]
                if clean.endswith('```'):
                    clean = clean[:-3]
                clean = clean.strip()
                
                print(f"\nTrying cleaned version ({len(clean)} chars)...")
                try:
                    parsed = json.loads(clean)
                    print("Cleaned JSON parse: SUCCESS")
                    print(f"Top-level keys: {list(parsed.keys())}")
                except json.JSONDecodeError as e2:
                    print(f"Cleaned JSON parse also failed: {e2}")
                    
        else:
            print("No response text")
            
        if result.get('error'):
            print(f"Error: {result.get('error')}")
            
    except Exception as e:
        print(f"Exception: {e}")
        elapsed = time.time() - start_time
        print(f"Elapsed: {elapsed:.1f}s")


if __name__ == "__main__":
    test_minimal_prompt()