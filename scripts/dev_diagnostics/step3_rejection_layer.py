#!/usr/bin/env python3
"""
Step 3: Enhanced response rejection layer.
"""

import os
import sys
import json
import re
import time
from datetime import datetime
from dotenv import load_dotenv
from typing import Dict, Any, List, Tuple, Optional

# Load environment variables
load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.llm_client import LLMClient
from src.utils.db import DatabaseClient


class ResponseRejector:
    """Enhanced response rejection layer for canonical output."""
    
    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self.required_keys = [
            "title", "cve_id", "vendor", "product", "severity", "description",
            "vulnerability_type", "affected_versions", "fixed_versions",
            "affected_platforms", "references", "retrieval_metadata",
            "workflows", "additional_recommendations"
        ]
        self.forbidden_keys = ["remediation_steps", "playbook"]
    
    def clean_response(self, raw_response: str) -> Tuple[str, Dict[str, Any]]:
        """Clean and analyze response."""
        analysis = {
            "original_length": len(raw_response),
            "has_markdown": False,
            "has_explanatory_text": False,
            "markdown_type": None,
            "cleaned_length": 0,
            "cleaning_applied": []
        }
        
        if not raw_response:
            return "", analysis
        
        clean_response = raw_response.strip()
        
        # Check for markdown
        if '```' in clean_response:
            analysis["has_markdown"] = True
            
            # Check for ```json
            if clean_response.startswith('```json'):
                analysis["markdown_type"] = "json_code_block"
                clean_response = clean_response[7:].strip()
                analysis["cleaning_applied"].append("removed ```json prefix")
            # Check for generic ```
            elif clean_response.startswith('```'):
                analysis["markdown_type"] = "code_block"
                clean_response = clean_response[3:].strip()
                analysis["cleaning_applied"].append("removed ``` prefix")
            
            # Remove trailing ```
            if clean_response.endswith('```'):
                clean_response = clean_response[:-3].strip()
                analysis["cleaning_applied"].append("removed ``` suffix")
        
        # Check for explanatory text
        lines = clean_response.split('\n')
        if len(lines) > 0:
            first_line = lines[0].strip()
            if not first_line.startswith('{') and not first_line.startswith('['):
                analysis["has_explanatory_text"] = True
                # Try to find JSON start
                for i, line in enumerate(lines):
                    if line.strip().startswith('{') or line.strip().startswith('['):
                        clean_response = '\n'.join(lines[i:]).strip()
                        analysis["cleaning_applied"].append(f"removed {i} lines of explanatory text")
                        break
        
        analysis["cleaned_length"] = len(clean_response)
        return clean_response.strip(), analysis
    
    def validate_response(self, raw_response: str) -> Tuple[bool, str, Optional[Dict], Dict[str, Any]]:
        """Validate response against rejection criteria."""
        validation_result = {
            "passed": False,
            "rejection_reason": None,
            "rejection_category": None,
            "analysis": {},
            "parsed_json": None,
            "missing_keys": [],
            "forbidden_keys_found": []
        }
        
        if not raw_response:
            validation_result["rejection_reason"] = "Empty response"
            validation_result["rejection_category"] = "EMPTY_RESPONSE"
            return False, "Empty response from LLM", None, validation_result
        
        # Clean and analyze
        clean_response, analysis = self.clean_response(raw_response)
        validation_result["analysis"] = analysis
        
        # Rejection: Markdown in strict mode
        if self.strict_mode and analysis["has_markdown"]:
            validation_result["rejection_reason"] = f"Response contains markdown code blocks ({analysis['markdown_type']})"
            validation_result["rejection_category"] = "MARKDOWN_WRAPPED"
            return False, validation_result["rejection_reason"], None, validation_result
        
        # Rejection: Explanatory text in strict mode
        if self.strict_mode and analysis["has_explanatory_text"]:
            validation_result["rejection_reason"] = "Response contains explanatory text before JSON"
            validation_result["rejection_category"] = "EXPLANATORY_TEXT"
            return False, validation_result["rejection_reason"], None, validation_result
        
        # Try to parse JSON
        try:
            parsed = json.loads(clean_response)
            validation_result["parsed_json"] = parsed
            
            # Check for forbidden keys
            if isinstance(parsed, dict):
                for key in self.forbidden_keys:
                    if key in parsed:
                        validation_result["forbidden_keys_found"].append(key)
                
                if validation_result["forbidden_keys_found"]:
                    validation_result["rejection_reason"] = f"Response contains forbidden keys: {validation_result['forbidden_keys_found']}"
                    validation_result["rejection_category"] = "FORBIDDEN_KEYS"
                    return False, validation_result["rejection_reason"], None, validation_result
                
                # Check required keys
                for key in self.required_keys:
                    if key not in parsed:
                        validation_result["missing_keys"].append(key)
                
                if validation_result["missing_keys"]:
                    validation_result["rejection_reason"] = f"Missing required keys: {validation_result['missing_keys']}"
                    validation_result["rejection_category"] = "MISSING_KEYS"
                    return False, validation_result["rejection_reason"], None, validation_result
                
                # Check workflows structure
                if "workflows" in parsed:
                    workflows = parsed["workflows"]
                    if not isinstance(workflows, list) or len(workflows) == 0:
                        validation_result["rejection_reason"] = "Workflows must be a non-empty list"
                        validation_result["rejection_category"] = "INVALID_WORKFLOWS"
                        return False, validation_result["rejection_reason"], None, validation_result
                
            validation_result["passed"] = True
            return True, "Response passed all validation checks", parsed, validation_result
            
        except json.JSONDecodeError as e:
            validation_result["rejection_reason"] = f"Invalid JSON: {str(e)}"
            validation_result["rejection_category"] = "INVALID_JSON"
            return False, validation_result["rejection_reason"], None, validation_result
        except Exception as e:
            validation_result["rejection_reason"] = f"Validation error: {str(e)}"
            validation_result["rejection_category"] = "VALIDATION_ERROR"
            return False, validation_result["rejection_reason"], None, validation_result


def test_rejection_layer():
    """Test the enhanced rejection layer."""
    print("VS.ai — Playbook Engine Gen-3")
    print("Prompt/Model Alignment Directive - Step 3")
    print("Enhanced Response Rejection Layer")
    print(f"Timestamp: {datetime.utcnow().isoformat()}")
    print("=" * 60)
    
    # Test cases
    test_cases = [
        {
            "name": "Perfect canonical JSON",
            "response": '''{
  "title": "Remediation Playbook for CVE-2023-4863",
  "cve_id": "CVE-2023-4863",
  "vendor": "Google",
  "product": "WebP",
  "severity": "HIGH",
  "description": "WebP heap buffer overflow vulnerability",
  "vulnerability_type": "Heap Buffer Overflow",
  "affected_versions": ["< 1.3.2"],
  "fixed_versions": ["1.3.2"],
  "affected_platforms": [],
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-4863"],
  "retrieval_metadata": {
    "decision": "strong",
    "evidence_count": 3,
    "source_indexes": ["canonical-generator"],
    "generation_timestamp": "2026-04-09T21:50:49.993319"
  },
  "workflows": [{
    "workflow_id": "workflow_1",
    "workflow_name": "Remediation Workflow",
    "workflow_type": "remediation",
    "steps": [{
      "step_number": 1,
      "title": "Upgrade WebP",
      "description": "Upgrade WebP to version 1.3.2 or later",
      "commands": ["apt-get update && apt-get install webp=1.3.2"],
      "target_os_or_platform": "Linux",
      "expected_result": "WebP upgraded to patched version",
      "verification": "Check webp --version",
      "evidence_based": true
    }]
  }],
  "additional_recommendations": []
}'''
        },
        {
            "name": "Markdown-wrapped JSON",
            "response": '''```json
{
  "title": "Remediation Playbook for CVE-2023-4863",
  "cve_id": "CVE-2023-4863",
  "vendor": "Google",
  "product": "WebP",
  "severity": "HIGH",
  "workflows": []
}
```'''
        },
        {
            "name": "With explanatory text",
            "response": '''Here is the remediation playbook for CVE-2023-4863:

{
  "title": "Remediation Playbook for CVE-2023-4863",
  "cve_id": "CVE-2023-4863",
  "vendor": "Google",
  "product": "WebP",
  "severity": "HIGH",
  "workflows": []
}'''
        },
        {
            "name": "Legacy remediation_steps",
            "response": '''{
  "title": "Remediation Playbook for CVE-2023-4863",
  "cve_id": "CVE-2023-4863",
  "vendor": "Google",
  "product": "WebP",
  "severity": "HIGH",
  "remediation_steps": [
    {"step": "Upgrade WebP"}
  ]
}'''
        },
        {
            "name": "Missing required keys",
            "response": '''{
  "title": "Remediation Playbook for CVE-2023-4863",
  "cve_id": "CVE-2023-4863",
  "vendor": "Google",
  "product": "WebP"
}'''
        }
    ]
    
    rejector = ResponseRejector(strict_mode=True)
    
    print("\nTesting rejection layer with strict mode...")
    print("-" * 60)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test_case['name']}")
        print(f"Response length: {len(test_case['response'])} chars")
        
        passed, reason, parsed, validation = rejector.validate_response(test_case['response'])
        
        print(f"  Result: {'PASS' if passed else 'REJECT'}")
        if not passed:
            print(f"  Reason: {reason}")
            print(f"  Category: {validation['rejection_category']}")
        
        analysis = validation.get('analysis', {})
        if analysis.get('has_markdown'):
            print(f"  Markdown detected: {analysis.get('markdown_type')}")
        if analysis.get('has_explanatory_text'):
            print(f"  Explanatory text detected")
        if validation.get('missing_keys'):
            print(f"  Missing keys: {validation['missing_keys']}")
        if validation.get('forbidden_keys_found'):
            print(f"  Forbidden keys: {validation['forbidden_keys_found']}")
    
    # Now test with actual LLM response from Step 2
    print(f"\n{'='*60}")
    print("Testing with actual LLM response from Step 2...")
    print(f"{'='*60}")
    
    # Load the saved response from Step 2
    try:
        import glob
        step2_files = glob.glob("logs/misc_runtime/step2_tightened_prompt_test_*.json")
        if step2_files:
            latest_file = max(step2_files, key=os.path.getctime)
            with open(latest_file, 'r') as f:
                step2_data = json.load(f)
            
            raw_response = step2_data.get('raw_response_excerpt', '')
            if len(raw_response) < 100:
                # Try to get full response from validation data
                validation_data = step2_data.get('validation', {})
                cleaned = validation_data.get('cleaned_response', '')
                if cleaned:
                    # Reconstruct with markdown for testing
                    raw_response = f"```json\n{cleaned}\n```"
            
            print(f"Loaded response from: {latest_file}")
            print(f"Response length: {len(raw_response)} chars")
            
            passed, reason, parsed, validation = rejector.validate_response(raw_response)
            
            print(f"\nValidation result: {'PASS' if passed else 'REJECT'}")
            if not passed:
                print(f"Rejection reason: {reason}")
                print(f"Category: {validation['rejection_category']}")
            
            # Test in non-strict mode (clean but don't reject)
            print(f"\n{'='*60}")
            print("Testing in non-strict mode (clean but don't reject)...")
            print(f"{'='*60}")
            
            rejector_non_strict = ResponseRejector(strict_mode=False)
            passed_ns, reason_ns, parsed_ns, validation_ns = rejector_non_strict.validate_response(raw_response)
            
            print(f"Result: {'PASS' if passed_ns else 'REJECT'}")
            if passed_ns and parsed_ns:
                print(f"Successfully parsed JSON with {len(list(parsed_ns.keys()))} keys")
                if 'workflows' in parsed_ns:
                    print(f"Workflows: {len(parsed_ns['workflows'])}")
            elif not passed_ns:
                print(f"Still rejected: {reason_ns}")
        
    except Exception as e:
        print(f"Error testing with Step 2 data: {e}")
    
    print(f"\n{'='*60}")
    print("STEP 3 RECOMMENDATIONS:")
    print(f"{'='*60}")
    print("1. Implement ResponseRejector in batch processor")
    print("2. Use strict_mode=True for production")
    print("3. Reject markdown-wrapped responses as GENERATION_FAIL")
    print("4. Clean responses in non-strict mode for testing")
    print("5. Add rejection categories to failure classification")
    
    # Save the rejector implementation
    output_file = f"step3_rejection_layer_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.py"
    with open(output_file, 'w') as f:
        f.write('''"""
ResponseRejector - Enhanced rejection layer for canonical output.
To integrate into batch processor:
1. Import ResponseRejector
2. Add after LLM call, before JSON parsing
3. Use strict_mode=True for production
4. Reject with appropriate failure classification
"""

import json
import re
from typing import Dict, Any, List, Tuple, Optional


class ResponseRejector:
    """Enhanced response rejection layer for canonical output."""
    
    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self.required_keys = [
            "title", "cve_id", "vendor", "product", "severity", "description",
            "vulnerability_type", "affected_versions", "fixed_versions",
            "affected_platforms", "references", "retrieval_metadata",
            "workflows", "additional_recommendations"
        ]
        self.forbidden_keys = ["remediation_steps", "playbook"]
    
    def clean_response(self, raw_response: str) -> Tuple[str, Dict[str, Any]]:
        """Clean and analyze response."""
        analysis = {
            "original_length": len(raw_response),
            "has_markdown": False,
            "has_explanatory_text": False,
            "markdown_type": None,
            "cleaned_length": 0,
            "cleaning_applied": []
        }
        
        if not raw_response:
            return "", analysis
        
        clean_response = raw_response.strip()
        
        # Check for markdown
        if '```' in clean_response:
            analysis["has_markdown"] = True
            
            # Check for ```json
            if clean_response.startswith('```json'):
                analysis["markdown_type"] = "json_code_block"
                clean_response = clean_response[7:].strip()
                analysis["cleaning_applied"].append("removed ```json prefix")
            # Check for generic ```
            elif clean_response.startswith('```'):
                analysis["markdown_type"] = "code_block"
                clean_response = clean_response[3:].strip()
                analysis["cleaning_applied"].append("removed ``` prefix")
            
            # Remove trailing ```
            if clean_response.endswith('```'):
                clean_response = clean_response[:-3].strip()
                analysis["cleaning_applied"].append("removed ``` suffix")
        
        # Check for explanatory text
        lines = clean_response.split('\\n')
        if len(lines) > 0:
            first_line = lines[0].strip()
            if not first_line.startswith('{') and not first_line.startswith('['):
                analysis["has_explanatory_text"] = True
                # Try to find JSON start
                for i, line in enumerate(lines):
                    if line.strip().startswith('{') or line.strip().startswith('['):
                        clean_response = '\\n'.join(lines[i:]).strip()
                        analysis["cleaning_applied"].append(f"removed {i} lines of explanatory text")
                        break
        
        analysis["cleaned_length"] = len(clean_response)
        return clean_response.strip(), analysis
    
    def validate_response(self, raw_response: str) -> Tuple[bool, str, Optional[Dict], Dict[str, Any]]:
        """Validate response against rejection criteria."""
        validation_result = {
            "passed": False,
            "rejection_reason": None,
            "rejection_category": None,
            "analysis": {},
            "parsed_json": None,
            "missing_keys": [],
            "forbidden_keys_found": []
        }
        
        if not raw_response:
            validation_result["rejection_reason"] = "Empty response"
            validation_result["rejection_category"] = "EMPTY_RESPONSE"
            return False, "Empty response from LLM", None, validation_result
        
        # Clean and analyze
        clean_response, analysis = self.clean_response(raw_response)
        validation_result["analysis"] = analysis
        
        # Rejection: Markdown in strict mode
        if self.strict_mode and analysis["has_markdown"]:
            validation_result["rejection_reason"] = f"Response contains markdown code blocks ({analysis['markdown_type']})"
            validation_result["rejection_category"] = "MARKDOWN_WRAPPED"
            return False, validation_result["rejection_reason"], None, validation_result
        
        # Rejection: Explanatory text in strict mode
        if self.strict_mode and analysis["has_explanatory_text"]:
            validation_result["rejection_reason"] = "Response contains explanatory text before JSON"
            validation_result["rejection_category"] = "EXPLANATORY_TEXT"
            return False, validation_result["rejection_reason"], None, validation_result
        
        # Try to parse JSON
        try:
            parsed = json.loads(clean_response)
            validation_result["parsed_json"] = parsed
            
            # Check for forbidden keys
            if isinstance(parsed, dict):
                for key in self.forbidden_keys:
                    if key in parsed:
                        validation_result["forbidden_keys_found"].append(key)
                
                if validation_result["forbidden_keys_found"]:
                    validation_result["rejection_reason"] = f"Response contains forbidden keys: {validation_result['forbidden_keys_found']}"
                    validation_result["rejection_category"] = "FORBIDDEN_KEYS"
                    return False, validation_result["rejection_reason"], None, validation_result
                
                # Check required keys
                for key in self.required_keys:
                    if key not in parsed:
                        validation_result["missing_keys"].append(key)
                
                if validation_result["missing_keys"]:
                    validation_result["rejection_reason"] = f"Missing required keys: {validation_result['missing_keys']}"
                    validation_result["rejection_category"] = "MISSING_KEYS"
                    return False, validation_result["rejection_reason"], None, validation_result
                
                # Check workflows structure
                if "workflows" in parsed:
                    workflows = parsed["workflows"]
                    if not isinstance(workflows, list) or len(workflows) == 0:
                        validation_result["rejection_reason"] = "Workflows must be a non-empty list"
                        validation_result["rejection_category"] = "INVALID_WORKFLOWS"
                        return False, validation_result["rejection_reason"], None, validation_result
                
            validation_result["passed"] = True
            return True, "Response passed all validation checks", parsed, validation_result
            
        except json.JSONDecodeError as e:
            validation_result["rejection_reason"] = f"Invalid JSON: {str(e)}"
            validation_result["rejection_category"] = "INVALID_JSON"
            return False, validation_result["rejection_reason"], None, validation_result
        except Exception as e:
            validation_result["rejection_reason"] = f"Validation error: {str(e)}"
            validation_result["rejection_category"] = "VALIDATION_ERROR"
            return False, validation_result["rejection_reason"], None, validation_result


# Integration example for batch processor:
def integrate_with_batch_processor():
    """
    Example integration with batch processor's generate_canonical_playbook_real function:
    
    # After LLM call, before JSON parsing:
    rejector = ResponseRejector(strict_mode=production_mode)
    passed, reason, parsed, validation = rejector.validate_response(actual_response)
    
    if not passed:
        # Classify failure based on rejection_category
        if validation["rejection_category"] in ["MARKDOWN_WRAPPED", "EXPLANATORY_TEXT", "INVALID_JSON"]:
            return False, f"LLM response validation failed: {reason}", None, actual_prompt, actual_response, "live_llm_failed", model_used
        elif validation["rejection_category"] in ["FORBIDDEN_KEYS", "MISSING_KEYS", "INVALID_WORKFLOWS"]:
            return False, f"Canonical schema violation: {reason}", None, actual_prompt, actual_response, "live_llm_failed", model_used
    
    # If passed, use parsed JSON
    playbook = parsed
    """
    pass
''')
    
    print(f"\nRejector implementation saved to: {output_file}")
    print("\nProceed to Step 4: Test CVE-2023-4863 with full pipeline.")


if __name__ == "__main__":
    test_rejection_layer()