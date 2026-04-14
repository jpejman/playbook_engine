#!/usr/bin/env python3
"""
Step 2: Test tightened prompt for canonical output.
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


def create_tightened_prompt(cve_id: str, context_data: dict) -> str:
    """Create tightened prompt for canonical output."""
    context_json = json.dumps(context_data, indent=2)
    
    prompt = f"""Generate a canonical remediation playbook for CVE {cve_id}.

## CVE Context Data
{context_json}

## CANONICAL OUTPUT REQUIREMENTS

1. **OUTPUT FORMAT**: Valid JSON only, no markdown, no code blocks, no explanatory text.

2. **REQUIRED TOP-LEVEL KEYS** (exact spelling):
   - title (string)
   - cve_id (string)
   - vendor (string)
   - product (string)
   - severity (string)
   - description (string)
   - vulnerability_type (string)
   - affected_versions (array)
   - fixed_versions (array)
   - affected_platforms (array)
   - references (array)
   - retrieval_metadata (object)
   - workflows (array) - REQUIRED, non-empty
   - additional_recommendations (array)

3. **WORKFLOWS STRUCTURE**:
   - workflows must be an array of workflow objects
   - Each workflow must have: workflow_id, workflow_name, workflow_type, steps
   - steps must be an array of step objects
   - Each step must have: step_number, title, description, commands, target_os_or_platform, expected_result, verification, evidence_based

4. **FORBIDDEN KEYS** (DO NOT USE):
   - remediation_steps (obsolete)
   - playbook (wrapper key)
   - Any key not listed in REQUIRED TOP-LEVEL KEYS

5. **INVALID IF**:
   - Output contains markdown code blocks (```)
   - Output contains explanatory text before/after JSON
   - Missing workflows array
   - Contains remediation_steps key
   - Contains playbook wrapper key
   - JSON is malformed

6. **EXAMPLES OF INVALID OUTPUT**:
   - ```json{{...}}``` (markdown)
   - "Here is the playbook:" {{...}} (explanatory text)
   - {{"playbook": {{...}}}} (wrapper)
   - {{"remediation_steps": [...]}} (legacy)

## GENERATION INSTRUCTIONS

Generate ONLY the JSON playbook object.
Start with {{ and end with }}.
Do not wrap in markdown.
Do not add explanatory text.
Use the exact canonical schema above.

## CANONICAL SCHEMA TEMPLATE

{{
  "title": "Remediation Playbook for {cve_id}",
  "cve_id": "{cve_id}",
  "vendor": "{context_data.get('vendor', '')}",
  "product": "{context_data.get('product', '')}",
  "severity": "{context_data.get('severity', '')}",
  "description": "{context_data.get('description', '')}",
  "vulnerability_type": "{context_data.get('vulnerability_type', '')}",
  "affected_versions": {json.dumps(context_data.get('affected_versions', []))},
  "fixed_versions": {json.dumps(context_data.get('fixed_versions', []))},
  "affected_platforms": {json.dumps(context_data.get('affected_platforms', []))},
  "references": {json.dumps(context_data.get('references', []))},
  "retrieval_metadata": {{
    "decision": "strong",
    "evidence_count": 3,
    "source_indexes": ["canonical-generator"],
    "generation_timestamp": "{datetime.utcnow().isoformat()}"
  }},
  "workflows": [
    {{
      "workflow_id": "workflow_1",
      "workflow_name": "Remediation Workflow",
      "workflow_type": "remediation",
      "steps": [
        {{
          "step_number": 1,
          "title": "Check current version",
          "description": "Verify the current version",
          "commands": ["command1", "command2"],
          "target_os_or_platform": "Linux",
          "expected_result": "Version identified",
          "verification": "Check version output",
          "evidence_based": true
        }}
      ]
    }}
  ],
  "additional_recommendations": []
}}

## FINAL INSTRUCTION

Generate the JSON playbook now. Output ONLY the JSON object."""
    
    return prompt


def validate_response(raw_response: str) -> dict:
    """Validate LLM response against tightened requirements."""
    validation = {
        "has_json": False,
        "json_error": None,
        "has_markdown": False,
        "has_explanatory_text": False,
        "has_workflows": False,
        "has_remediation_steps": False,
        "has_playbook_wrapper": False,
        "missing_required_keys": [],
        "parsed_json": None,
        "cleaned_response": None
    }
    
    if not raw_response:
        validation["json_error"] = "Empty response"
        return validation
    
    # Check for markdown
    if '```' in raw_response:
        validation["has_markdown"] = True
    
    # Check for explanatory text
    lines = raw_response.strip().split('\n')
    if len(lines) > 0:
        first_line = lines[0].strip()
        if not first_line.startswith('{') and not first_line.startswith('['):
            validation["has_explanatory_text"] = True
    
    # Clean response
    clean_response = raw_response.strip()
    if clean_response.startswith('```json'):
        clean_response = clean_response[7:]
    if clean_response.startswith('```'):
        clean_response = clean_response[3:]
    if clean_response.endswith('```'):
        clean_response = clean_response[:-3]
    clean_response = clean_response.strip()
    
    validation["cleaned_response"] = clean_response
    
    # Try to parse JSON
    try:
        parsed = json.loads(clean_response)
        validation["has_json"] = True
        validation["parsed_json"] = parsed
        
        # Check for forbidden keys
        if isinstance(parsed, dict):
            if "remediation_steps" in parsed:
                validation["has_remediation_steps"] = True
            if "playbook" in parsed:
                validation["has_playbook_wrapper"] = True
            if "workflows" in parsed:
                validation["has_workflows"] = True
                if not isinstance(parsed["workflows"], list) or len(parsed["workflows"]) == 0:
                    validation["missing_required_keys"].append("workflows (empty or not list)")
            
            # Check required keys
            required_keys = [
                "title", "cve_id", "vendor", "product", "severity", "description",
                "vulnerability_type", "affected_versions", "fixed_versions",
                "affected_platforms", "references", "retrieval_metadata",
                "workflows", "additional_recommendations"
            ]
            
            for key in required_keys:
                if key not in parsed:
                    validation["missing_required_keys"].append(key)
                    
    except json.JSONDecodeError as e:
        validation["json_error"] = str(e)
    
    return validation


def test_tightened_prompt():
    """Test the tightened prompt."""
    print("VS.ai — Playbook Engine Gen-3")
    print("Prompt/Model Alignment Directive - Step 2")
    print("Test Tightened Prompt for Canonical Output")
    print(f"Timestamp: {datetime.utcnow().isoformat()}")
    print("=" * 60)
    
    cve_id = "CVE-2023-4863"
    
    # Get context
    context = get_cve_context(cve_id)
    if not context:
        print(f"ERROR: No context for {cve_id}")
        return
    
    # Create tightened prompt
    prompt = create_tightened_prompt(cve_id, context)
    
    print(f"\nGenerated prompt length: {len(prompt)} chars")
    print(f"\nPrompt excerpt (first 500 chars):")
    print("-" * 60)
    print(prompt[:500] + "..." if len(prompt) > 500 else prompt)
    print("-" * 60)
    
    # Call LLM
    llm = LLMClient()
    print(f"\nCalling LLM (model: {llm.model}, timeout: {llm.timeout_seconds}s)...")
    
    start_time = time.time()
    result = llm.generate(prompt)
    elapsed = time.time() - start_time
    
    print(f"\nLLM call completed in {elapsed:.1f}s")
    print(f"Status: {result.get('status')}")
    
    raw_response = result.get('raw_text', '')
    print(f"Response length: {len(raw_response)} chars")
    
    if raw_response:
        print(f"\nRaw response (first 1000 chars):")
        print("-" * 60)
        print(raw_response[:1000])
        if len(raw_response) > 1000:
            print("...")
        print("-" * 60)
        
        # Validate
        validation = validate_response(raw_response)
        
        print(f"\nVALIDATION RESULTS:")
        print(f"  Has JSON: {validation['has_json']}")
        if validation['json_error']:
            print(f"  JSON error: {validation['json_error']}")
        print(f"  Has markdown: {validation['has_markdown']}")
        print(f"  Has explanatory text: {validation['has_explanatory_text']}")
        print(f"  Has workflows: {validation['has_workflows']}")
        print(f"  Has remediation_steps: {validation['has_remediation_steps']}")
        print(f"  Has playbook wrapper: {validation['has_playbook_wrapper']}")
        
        if validation['has_json'] and validation['parsed_json']:
            print(f"\nPARSED JSON ANALYSIS:")
            parsed = validation['parsed_json']
            print(f"  Top-level keys: {list(parsed.keys())}")
            
            if 'workflows' in parsed:
                workflows = parsed['workflows']
                print(f"  Workflows count: {len(workflows)}")
                if workflows and len(workflows) > 0:
                    first_wf = workflows[0]
                    print(f"  First workflow keys: {list(first_wf.keys())}")
                    if 'steps' in first_wf:
                        print(f"  Steps in first workflow: {len(first_wf['steps'])}")
            
            if validation['missing_required_keys']:
                print(f"  Missing required keys: {validation['missing_required_keys']}")
            else:
                print(f"  All required keys present!")
        
        # Save results
        import os
        os.makedirs("logs/misc_runtime", exist_ok=True)
        output_file = f"logs/misc_runtime/step2_tightened_prompt_test_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump({
                "cve_id": cve_id,
                "timestamp": datetime.utcnow().isoformat(),
                "model": llm.model,
                "elapsed_seconds": round(elapsed, 2),
                "prompt_excerpt": prompt[:500] + "..." if len(prompt) > 500 else prompt,
                "response_length": len(raw_response),
                "validation": validation,
                "raw_response_excerpt": raw_response[:2000] if len(raw_response) > 2000 else raw_response
            }, f, indent=2, default=str)
        
        print(f"\nResults saved to: {output_file}")
        
        # Final assessment
        print(f"\n{'='*60}")
        print("STEP 2 ASSESSMENT:")
        print(f"{'='*60}")
        
        issues = []
        if not validation['has_json']:
            issues.append("No valid JSON")
        if validation['has_markdown']:
            issues.append("Contains markdown")
        if validation['has_explanatory_text']:
            issues.append("Contains explanatory text")
        if validation['has_remediation_steps']:
            issues.append("Contains legacy remediation_steps")
        if validation['has_playbook_wrapper']:
            issues.append("Contains playbook wrapper")
        if validation['missing_required_keys']:
            issues.append(f"Missing keys: {validation['missing_required_keys']}")
        
        if not issues:
            print("SUCCESS: Response meets all tightened requirements!")
            print("Proceed to Step 3: Add response rejection layer.")
        else:
            print(f"ISSUES FOUND: {len(issues)}")
            for i, issue in enumerate(issues, 1):
                print(f"  {i}. {issue}")
            print("\nNeed to further tighten prompt or add rejection layer.")
    else:
        print("No response from LLM")
        if result.get('error'):
            print(f"Error: {result.get('error')}")


if __name__ == "__main__":
    test_tightened_prompt()