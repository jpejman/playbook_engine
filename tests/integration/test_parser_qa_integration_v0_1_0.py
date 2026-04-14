#!/usr/bin/env python3
"""
Parser and QA Integration Test
Version: v0.1.0
Timestamp: 2026-04-08

Purpose:
- Test integrated parser and QA workflow
- Show real LLM response parsing and evaluation
- Provide raw test output as required
"""

import os
import sys
import json
import logging
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
env_path = Path(__file__).parent.parent.parent / '.env'
load_dotenv(env_path)

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.utils.playbook_parser import parse_playbook_response
from src.utils.qa_evaluator import evaluate_playbook_qa
from src.utils.llm_client import LLMClient

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_valid_sample():
    """Test with a valid playbook sample."""
    print("=" * 60)
    print("TEST 1: VALID PLAYBOOK SAMPLE")
    print("=" * 60)
    
    valid_json = '''{
        "playbook": {
            "title": "Remediation Playbook for CVE-TEST-0001",
            "cve_id": "CVE-TEST-0001",
            "severity": "High",
            "affected_components": ["test-product", "network-services"],
            "remediation_steps": [
                {
                    "step_number": 1,
                    "description": "Isolate affected systems",
                    "commands": ["iptables -A INPUT -s <affected_ip> -j DROP"],
                    "verification": "Confirm network isolation"
                },
                {
                    "step_number": 2,
                    "description": "Apply security patches",
                    "commands": ["apt-get update && apt-get upgrade test-product --security"],
                    "verification": "Verify patch installation"
                }
            ],
            "verification_procedures": ["Run vulnerability scan"],
            "rollback_procedures": ["Restore from backup"],
            "references": ["https://example.local/test-cve"],
            "retrieval_metadata": {
                "decision": "sufficient",
                "evidence_count": 5,
                "sources": ["spring-ai-document-index"]
            }
        }
    }'''
    
    print("\n1. Raw input (first 200 chars):")
    print(valid_json[:200] + "...")
    
    print("\n2. Parser output:")
    parser_result = parse_playbook_response(valid_json)
    print(f"   Parsed OK: {parser_result['parsed_ok']}")
    print(f"   Parse errors: {parser_result['parse_errors']}")
    
    if parser_result['parsed_playbook']:
        playbook = parser_result['parsed_playbook'].get('playbook', {})
        print(f"   Playbook title: {playbook.get('title', 'N/A')}")
        print(f"   Remediation steps: {len(playbook.get('remediation_steps', []))}")
    
    print("\n3. QA evaluation:")
    qa_result = evaluate_playbook_qa(
        raw_response=valid_json,
        parsed_playbook=parser_result['parsed_playbook'],
        parse_errors=parser_result['parse_errors'],
        has_retrieval_backing=True
    )
    
    print(f"   QA Result: {qa_result['qa_result']}")
    print(f"   QA Score: {qa_result['qa_score']:.3f}")
    print(f"   QA Errors: {qa_result['qa_feedback']['errors']}")
    print(f"   QA Warnings: {qa_result['qa_feedback']['warnings']}")
    print(f"   QA Strengths: {qa_result['qa_feedback']['strengths']}")
    
    return parser_result, qa_result


def test_malformed_sample():
    """Test with a malformed playbook sample."""
    print("\n" + "=" * 60)
    print("TEST 2: MALFORMED PLAYBOOK SAMPLE")
    print("=" * 60)
    
    malformed_json = '''{
        "playbook": {
            "title": "Bad Playbook",
            "cve_id": "CVE-TEST-0002",
            "remediation_steps": [
                {
                    "step_number": 1,
                    "description": "Missing closing brace"
    }'''
    
    print("\n1. Raw input:")
    print(malformed_json)
    
    print("\n2. Parser output:")
    parser_result = parse_playbook_response(malformed_json)
    print(f"   Parsed OK: {parser_result['parsed_ok']}")
    print(f"   Parse errors: {parser_result['parse_errors']}")
    
    print("\n3. QA evaluation:")
    qa_result = evaluate_playbook_qa(
        raw_response=malformed_json,
        parsed_playbook=parser_result['parsed_playbook'],
        parse_errors=parser_result['parse_errors'],
        has_retrieval_backing=False
    )
    
    print(f"   QA Result: {qa_result['qa_result']}")
    print(f"   QA Score: {qa_result['qa_score']:.3f}")
    print(f"   QA Errors: {qa_result['qa_feedback']['errors']}")
    
    return parser_result, qa_result


def test_real_llm_response():
    """Test with a real LLM response."""
    print("\n" + "=" * 60)
    print("TEST 3: REAL LLM RESPONSE (WITH OLLAMA)")
    print("=" * 60)
    
    # Initialize LLM client
    client = LLMClient()
    print(f"Using model: {client.model}")
    print(f"Base URL: {client.base_url}")
    
    # Create test prompt
    test_prompt = '''Create a simple remediation playbook for CVE-TEST-0001.

Output in JSON format with this structure:
{
  "playbook": {
    "title": "string",
    "cve_id": "string",
    "severity": "string",
    "remediation_steps": [
      {
        "step_number": 1,
        "description": "string"
      }
    ]
  }
}'''
    
    print(f"\n1. Test prompt length: {len(test_prompt)} chars")
    print(f"Prompt preview: {test_prompt[:100]}...")
    
    # Call LLM
    print("\n2. Calling LLM...")
    llm_result = client.generate(test_prompt)
    
    print(f"   Status: {llm_result['status']}")
    print(f"   Model: {llm_result['model']}")
    print(f"   Response length: {len(llm_result.get('raw_text', ''))} chars")
    
    if llm_result['status'] == 'completed':
        raw_response = llm_result['raw_text']
        
        print("\n3. Parser output:")
        parser_result = parse_playbook_response(raw_response)
        print(f"   Parsed OK: {parser_result['parsed_ok']}")
        print(f"   Parse errors: {parser_result['parse_errors']}")
        
        if parser_result['parsed_playbook']:
            playbook = parser_result['parsed_playbook'].get('playbook', {})
            print(f"   Playbook title: {playbook.get('title', 'N/A')}")
        
        print("\n4. QA evaluation:")
        qa_result = evaluate_playbook_qa(
            raw_response=raw_response,
            parsed_playbook=parser_result['parsed_playbook'],
            parse_errors=parser_result['parse_errors'],
            has_retrieval_backing=False
        )
        
        print(f"   QA Result: {qa_result['qa_result']}")
        print(f"   QA Score: {qa_result['qa_score']:.3f}")
        print(f"   QA Errors: {qa_result['qa_feedback']['errors']}")
        print(f"   QA Warnings: {qa_result['qa_feedback']['warnings']}")
        
        # Show response snippet
        print(f"\n5. Response snippet (first 300 chars):")
        print(raw_response[:300] + ("..." if len(raw_response) > 300 else ""))
    
    return llm_result


def main():
    """Main test execution."""
    print("PARSER AND QA INTEGRATION TEST")
    print("=" * 60)
    
    try:
        # Test 1: Valid sample
        parser_result1, qa_result1 = test_valid_sample()
        
        # Test 2: Malformed sample
        parser_result2, qa_result2 = test_malformed_sample()
        
        # Test 3: Real LLM response
        llm_result = test_real_llm_response()
        
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Test 1 (Valid): Parser OK={parser_result1['parsed_ok']}, QA={qa_result1['qa_result']}")
        print(f"Test 2 (Malformed): Parser OK={parser_result2['parsed_ok']}, QA={qa_result2['qa_result']}")
        
        if llm_result['status'] == 'completed':
            print(f"Test 3 (Real LLM): Status=completed, Response length={len(llm_result.get('raw_text', ''))} chars")
        else:
            print(f"Test 3 (Real LLM): Status=failed, Error={llm_result.get('error', 'Unknown')}")
        
        print("\n✅ Parser and QA integration tests completed")
        
    except Exception as e:
        print(f"\n❌ Test failed with exception: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()