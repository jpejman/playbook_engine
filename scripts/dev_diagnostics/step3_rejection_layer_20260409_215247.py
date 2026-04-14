"""
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
