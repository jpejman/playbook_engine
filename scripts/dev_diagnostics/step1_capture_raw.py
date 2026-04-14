#!/usr/bin/env python3
"""
Step 1: Capture raw live outputs for analysis.
Focus on getting exact failure modes.
"""

import os
import sys
import json
import time
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.llm_client import LLMClient
from src.utils.db import DatabaseClient


def get_cve_context(cve_id: str):
    """Get CVE context from database."""
    db = DatabaseClient()
    query = """
    SELECT context_data 
    FROM cve_context_snapshot 
    WHERE cve_id = %s 
    ORDER BY created_at DESC 
    LIMIT 1
    """
    result = db.fetch_one(query, (cve_id,))
    if result and result.get('context_data'):
        return result['context_data']
    return None


def create_current_prompt(cve_id: str, context_data: dict) -> str:
    """Create current generation prompt."""
    context_json = json.dumps(context_data, indent=2)
    
    prompt = f"""Generate a canonical remediation playbook for CVE {cve_id}.

## CVE Context Data
{context_json}

## Instructions
Generate a comprehensive remediation playbook in canonical JSON format with:
1. Title including CVE ID
2. Accurate vendor and product information
3. Specific remediation steps with real commands (not echo statements)
4. Pre-remediation checks
5. Post-remediation validation
6. Evidence-based recommendations

## Output Schema
The playbook must be valid JSON matching the canonical schema with workflows, steps, commands, etc.

Generate only the JSON playbook, no additional text."""
    
    return prompt


def analyze_response(raw_response: str) -> dict:
    """Analyze LLM response for failure modes."""
    analysis = {
        "has_json": False,
        "json_error": None,
        "has_remediation_steps": False,
        "has_workflows": False,
        "has_playbook_wrapper": False,
        "has_markdown": False,
        "has_explanatory_text": False,
        "parsed_json": None
    }
    
    if not raw_response:
        analysis["json_error"] = "Empty response"
        return analysis
    
    # Check for markdown code blocks
    if '```' in raw_response:
        analysis["has_markdown"] = True
    
    # Check for explanatory text
    lines = raw_response.strip().split('\n')
    if len(lines) > 1:
        first_line = lines[0].strip().lower()
        if not first_line.startswith('{') and not first_line.startswith('['):
            analysis["has_explanatory_text"] = True
    
    # Clean response for JSON parsing
    clean_response = raw_response.strip()
    if clean_response.startswith('```json'):
        clean_response = clean_response[7:]
    if clean_response.startswith('```'):
        clean_response = clean_response[3:]
    if clean_response.endswith('```'):
        clean_response = clean_response[:-3]
    clean_response = clean_response.strip()
    
    # Try to parse JSON
    try:
        parsed = json.loads(clean_response)
        analysis["has_json"] = True
        analysis["parsed_json"] = parsed
        
        # Check for specific keys
        if isinstance(parsed, dict):
            if "remediation_steps" in parsed:
                analysis["has_remediation_steps"] = True
            if "workflows" in parsed:
                analysis["has_workflows"] = True
            if "playbook" in parsed:
                analysis["has_playbook_wrapper"] = True
                
    except json.JSONDecodeError as e:
        analysis["json_error"] = str(e)
    
    return analysis


def capture_one(cve_id: str, attempt: int) -> dict:
    """Capture one live generation with analysis."""
    print(f"\n[ATTEMPT {attempt}] {cve_id}")
    print("-" * 40)
    
    # Get context
    context = get_cve_context(cve_id)
    if not context:
        print("ERROR: No context data")
        return None
    
    # Create prompt
    prompt = create_current_prompt(cve_id, context)
    
    # Call LLM
    llm = LLMClient()
    print(f"Calling LLM (model: {llm.model})...")
    start_time = time.time()
    
    try:
        result = llm.generate(prompt)
        elapsed = time.time() - start_time
        
        if result.get('status') != 'completed':
            print(f"LLM failed: {result.get('error', 'Unknown error')}")
            return None
        
        raw_response = result.get('raw_text', '')
        print(f"Response received ({len(raw_response)} chars, {elapsed:.1f}s)")
        
        # Analyze response
        analysis = analyze_response(raw_response)
        
        # Display analysis
        print("\nANALYSIS:")
        print(f"  Valid JSON: {analysis['has_json']}")
        if analysis['json_error']:
            print(f"  JSON error: {analysis['json_error']}")
        print(f"  Has remediation_steps: {analysis['has_remediation_steps']}")
        print(f"  Has workflows: {analysis['has_workflows']}")
        print(f"  Has playbook wrapper: {analysis['has_playbook_wrapper']}")
        print(f"  Has markdown: {analysis['has_markdown']}")
        print(f"  Has explanatory text: {analysis['has_explanatory_text']}")
        
        # Show excerpt
        print(f"\nRESPONSE EXCERPT (first 500 chars):")
        print("-" * 40)
        excerpt = raw_response[:500]
        if len(raw_response) > 500:
            excerpt += "..."
        print(excerpt)
        print("-" * 40)
        
        # Build capture result
        capture = {
            "cve_id": cve_id,
            "attempt": attempt,
            "timestamp": datetime.utcnow().isoformat(),
            "model": llm.model,
            "elapsed_seconds": round(elapsed, 2),
            "prompt_excerpt": prompt[:300] + "..." if len(prompt) > 300 else prompt,
            "response_length": len(raw_response),
            "analysis": analysis,
            "raw_response_excerpt": raw_response[:1000] if len(raw_response) > 1000 else raw_response
        }
        
        return capture
        
    except Exception as e:
        print(f"Error during capture: {e}")
        return None


def main():
    """Main capture function."""
    print("VS.ai — Playbook Engine Gen-3")
    print("Prompt/Model Alignment Directive - Step 1")
    print("Capture Raw Live Outputs")
    print(f"Timestamp: {datetime.utcnow().isoformat()}")
    print("=" * 60)
    
    cve_id = "CVE-2023-4863"
    captures = []
    
    # Capture 3 live outputs
    for i in range(1, 4):
        print(f"\n{'='*60}")
        print(f"CAPTURE {i}/3")
        print(f"{'='*60}")
        
        capture = capture_one(cve_id, i)
        if capture:
            captures.append(capture)
            
            # Save after each capture
            output_file = f"step1_capture_{i}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump(capture, f, indent=2, default=str)
            print(f"\nSaved to: {output_file}")
        
        # Brief pause between attempts
        if i < 3:
            print(f"\nWaiting 10 seconds before next attempt...")
            time.sleep(10)
    
    # Summary
    print(f"\n{'='*60}")
    print("STEP 1 SUMMARY")
    print(f"{'='*60}")
    
    if not captures:
        print("No captures collected")
        return
    
    total = len(captures)
    json_success = sum(1 for c in captures if c['analysis']['has_json'])
    has_workflows = sum(1 for c in captures if c['analysis']['has_workflows'])
    has_remediation_steps = sum(1 for c in captures if c['analysis']['has_remediation_steps'])
    
    print(f"Total captures: {total}")
    print(f"Valid JSON: {json_success}/{total}")
    print(f"Has workflows (canonical): {has_workflows}/{total}")
    print(f"Has remediation_steps (legacy): {has_remediation_steps}/{total}")
    
    # Failure modes
    print("\nFAILURE MODES OBSERVED:")
    for i, capture in enumerate(captures, 1):
        analysis = capture['analysis']
        print(f"\nCapture {i}:")
        if not analysis['has_json']:
            print(f"  - JSON parse error: {analysis['json_error']}")
        if analysis['has_remediation_steps']:
            print(f"  - Contains legacy 'remediation_steps' key")
        if analysis['has_markdown']:
            print(f"  - Contains markdown code blocks")
        if analysis['has_explanatory_text']:
            print(f"  - Contains explanatory text before JSON")
        if analysis['has_playbook_wrapper']:
            print(f"  - Has 'playbook' wrapper key")
    
    # Save final summary
    summary_file = f"step1_summary_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(summary_file, 'w') as f:
        json.dump({
            "summary": {
                "total_captures": total,
                "json_success": json_success,
                "has_workflows": has_workflows,
                "has_remediation_steps": has_remediation_steps,
                "timestamp": datetime.utcnow().isoformat()
            },
            "captures": captures
        }, f, indent=2, default=str)
    
    print(f"\nSummary saved to: {summary_file}")
    print("\nProceed to Step 2: Tighten prompt for canonical output.")


if __name__ == "__main__":
    main()