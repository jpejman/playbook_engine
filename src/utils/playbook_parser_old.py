#!/usr/bin/env python3
"""
Playbook Response Parser
Version: v0.2.0
Timestamp: 2026-04-13

Purpose:
- Parse LLM responses into structured playbook format
- Handle JSON parsing with markdown fence stripping
- Support both legacy and canonical schema formats
- Provide clear error messages for malformed output
"""

import json
import re
import logging
from typing import Dict, Any, List, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PlaybookParser:
    """Parser for LLM playbook responses with support for multiple schemas."""
    
    def __init__(self):
        pass
    
    def parse_playbook_response(self, raw_text: str) -> Dict[str, Any]:
        """
        Parse LLM response into playbook format.
        
        Args:
            raw_text: Raw text response from LLM
            
        Returns:
            Dictionary with structure:
            {
                "parsed_ok": True | False,
                "parsed_playbook": dict | None,
                "parse_errors": list[str]
            }
        """
        parse_errors: List[str] = []
        parsed_playbook: Optional[Dict[str, Any]] = None
        
        if not raw_text or not raw_text.strip():
            parse_errors.append("Empty response received")
            return {
                "parsed_ok": False,
                "parsed_playbook": None,
                "parse_errors": parse_errors
            }
        
        # Clean the text
        cleaned_text = raw_text.strip()
        
        # Try direct JSON parse first
        parsed_data = self._try_json_parse(cleaned_text, parse_errors)
        
        if parsed_data is None:
            # Try stripping markdown fences
            text_without_fences = self._strip_markdown_fences(cleaned_text)
            if text_without_fences != cleaned_text:
                logger.info(f"Stripped markdown fences and retrying parse. Original: {len(cleaned_text)} chars, After: {len(text_without_fences)} chars")
                parsed_data = self._try_json_parse(text_without_fences, parse_errors)
        
        if parsed_data is not None:
            # Validate playbook structure
            if self._validate_playbook_structure(parsed_data, parse_errors):
                parsed_playbook = parsed_data
            else:
                parsed_data = None
        
        parsed_ok = parsed_playbook is not None and len(parse_errors) == 0
        
        return {
            "parsed_ok": parsed_ok,
            "parsed_playbook": parsed_playbook,
            "parse_errors": parse_errors
        }


def try_json_parse(text: str, errors: List[str]) -> Optional[Dict[str, Any]]:
    """
    Attempt to parse text as JSON.
    
    Args:
        text: Text to parse
        errors: List to append errors to
        
    Returns:
        Parsed dictionary or None
    """
    # First try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        first_error = str(e)
    
    # If direct parse fails, try to extract JSON from text
    json_match = find_json_in_text(text)
    if json_match:
        try:
            logger.info(f"Found JSON-like content in text ({len(json_match)} chars), attempting parse")
            return json.loads(json_match)
        except json.JSONDecodeError as e2:
            errors.append(f"JSON parse error (extracted): {str(e2)}")
            return None
    else:
        errors.append(f"JSON parse error: {first_error}")
        return None


def strip_markdown_fences(text: str) -> str:
    """
    Strip markdown code fences from text.
    
    Args:
        text: Text potentially containing markdown fences
        
    Returns:
        Text with fences removed
    """
    # Pattern for ```json ... ``` or ``` ... ```
    pattern = r'^```(?:json)?\s*\n?(.*?)\n?```$'
    
    # Check if entire text is wrapped in fences
    match = re.match(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # Also handle cases where fences might be at start/end but not both
    # Remove leading ```json or ```
    text = re.sub(r'^```(?:json)?\s*\n?', '', text, flags=re.MULTILINE)
    # Remove trailing ```
    text = re.sub(r'\n?```$', '', text, flags=re.MULTILINE)
    
    return text.strip()


def find_json_in_text(text: str) -> Optional[str]:
    """
    Find JSON-like content in text.
    
    Args:
        text: Text to search
        
    Returns:
        JSON string if found, None otherwise
    """
    # Look for {...} pattern with balanced braces
    brace_depth = 0
    start_index = -1
    json_candidates = []
    
    for i, char in enumerate(text):
        if char == '{':
            if brace_depth == 0:
                start_index = i
            brace_depth += 1
        elif char == '}':
            brace_depth -= 1
            if brace_depth == 0 and start_index != -1:
                json_candidates.append(text[start_index:i+1])
                start_index = -1
    
    # Try candidates from longest to shortest
    for candidate in sorted(json_candidates, key=len, reverse=True):
        try:
            # Quick validation - should start with { and end with }
            if candidate.strip().startswith('{') and candidate.strip().endswith('}'):
                # Try to parse to validate
                json.loads(candidate)
                return candidate
        except:
            continue
    
    return None


def validate_playbook_structure(parsed_data: Dict[str, Any], errors: List[str]) -> bool:
    """
    Validate parsed data has basic playbook structure.
    Supports both legacy schema (with 'playbook' key) and canonical schema.
    
    Args:
        parsed_data: Parsed dictionary
        errors: List to append errors to
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(parsed_data, dict):
        errors.append("Parsed data is not a dictionary")
        return False
    
    # Check for canonical schema first (new format)
    if self._is_canonical_schema(parsed_data):
        logger.info("Detected canonical schema format")
        # Transform canonical to legacy format for compatibility
        playbook = self._transform_canonical_to_legacy(parsed_data)
        return self._validate_legacy_structure(playbook, errors)
    
    # Check for legacy schema (with 'playbook' key)
    elif "playbook" in parsed_data:
        logger.info("Detected legacy schema format (with 'playbook' key)")
        playbook = parsed_data["playbook"]
        return self._validate_legacy_structure(playbook, errors)
    
    # Unknown schema
    else:
        errors.append("Response does not match either canonical or legacy schema format")
        # Try to extract any valid structure
        if self._has_playbook_like_structure(parsed_data):
            logger.info("Attempting to validate as direct playbook structure")
            return self._validate_legacy_structure(parsed_data, errors)
        return False

def _is_canonical_schema(self, data: Dict[str, Any]) -> bool:
    """Check if data matches canonical schema format."""
    # Canonical schema has 'header' with required fields
    if "header" not in data:
        return False
    
    header = data.get("header", {})
    required_canonical_fields = ["title", "cve_id", "vendor", "product", "severity"]
    
    # Check if header has canonical fields
    has_canonical_fields = all(field in header for field in required_canonical_fields)
    
    # Also check for other canonical indicators
    has_canonical_structure = "workflows" in data or "retrieval_metadata" in data
    
    return has_canonical_fields or has_canonical_structure

def _transform_canonical_to_legacy(self, canonical_data: Dict[str, Any]) -> Dict[str, Any]:
    """Transform canonical schema to legacy schema format."""
    legacy_playbook = {}
    
    # Extract from header
    header = canonical_data.get("header", {})
    legacy_playbook["title"] = header.get("title", "")
    legacy_playbook["cve_id"] = header.get("cve_id", "")
    legacy_playbook["severity"] = header.get("severity", "")
    
    # Handle affected_components
    if "affected_platforms" in canonical_data:
        legacy_playbook["affected_components"] = canonical_data["affected_platforms"]
    elif "affected_versions" in canonical_data:
        legacy_playbook["affected_components"] = [f"Version: {v}" for v in canonical_data["affected_versions"]]
    else:
        legacy_playbook["affected_components"] = [header.get("product", "Unknown")]
    
    # Transform workflows to remediation_steps
    if "workflows" in canonical_data:
        remediation_steps = []
        for i, workflow in enumerate(canonical_data["workflows"], 1):
            if isinstance(workflow, dict):
                step = {
                    "step_number": i,
                    "description": workflow.get("description", f"Workflow step {i}"),
                    "commands": workflow.get("commands", []),
                    "verification": workflow.get("verification", ""),
                    "evidence_based": workflow.get("evidence_based", False)
                }
                remediation_steps.append(step)
        legacy_playbook["remediation_steps"] = remediation_steps
    else:
        legacy_playbook["remediation_steps"] = []
    
    # Handle verification procedures
    if "post_remediation_validation" in canonical_data:
        legacy_playbook["verification_procedures"] = canonical_data["post_remediation_validation"]
    else:
        legacy_playbook["verification_procedures"] = ["Verify remediation was successful"]
    
    # Handle rollback procedures
    legacy_playbook["rollback_procedures"] = ["Restore from backup if available", "Revert configuration changes"]
    
    # Handle references
    if "references" in canonical_data:
        legacy_playbook["references"] = canonical_data["references"]
    else:
        legacy_playbook["references"] = []
    
    return legacy_playbook

def _has_playbook_like_structure(self, data: Dict[str, Any]) -> bool:
    """Check if data has playbook-like structure without explicit schema."""
    # Check for common playbook fields
    playbook_fields = ["title", "cve_id", "severity", "affected_components", "remediation_steps"]
    has_playbook_fields = any(field in data for field in playbook_fields)
    
    # Check for nested structure that might be a playbook
    has_nested_structure = any(isinstance(v, dict) for v in data.values()) or any(isinstance(v, list) for v in data.values())
    
    return has_playbook_fields or has_nested_structure

def _validate_legacy_structure(self, playbook: Dict[str, Any], errors: List[str]) -> bool:
    """
    Validate legacy playbook structure.
    
    Args:
        playbook: Playbook dictionary (either from 'playbook' key or transformed)
        errors: List to append errors to
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(playbook, dict):
        errors.append("Playbook data is not a dictionary")
        return False
    
    # Check for required fields (relaxed validation for transformed data)
    required_fields = ["title", "cve_id", "severity"]
    for field in required_fields:
        if field not in playbook:
            errors.append(f"Missing required field: '{field}'")
    
    # Check for affected_components
    if "affected_components" not in playbook:
        errors.append("Missing 'affected_components'")
    elif not isinstance(playbook["affected_components"], list):
        errors.append("'affected_components' is not a list")
    elif len(playbook["affected_components"]) == 0:
        errors.append("'affected_components' list is empty")
    
    # Check for remediation_steps
    if "remediation_steps" not in playbook:
        errors.append("Missing 'remediation_steps'")
    elif not isinstance(playbook["remediation_steps"], list):
        errors.append("'remediation_steps' is not a list")
    elif len(playbook["remediation_steps"]) == 0:
        errors.append("'remediation_steps' list is empty")
    else:
        # Validate each remediation step structure
        for i, step in enumerate(playbook["remediation_steps"]):
            if not isinstance(step, dict):
                errors.append(f"Remediation step {i+1} is not a dictionary")
                continue
                
            # Required step fields
            if "description" not in step:
                errors.append(f"Remediation step {i+1} missing 'description'")
            
            # Optional fields with type validation
            if "commands" in step and not isinstance(step["commands"], list):
                errors.append(f"Remediation step {i+1} 'commands' field is not a list")
            if "evidence_based" in step and not isinstance(step["evidence_based"], bool):
                errors.append(f"Remediation step {i+1} 'evidence_based' field is not a boolean")
    
    # Check for references (optional but recommended)
    if "references" not in playbook:
        logger.warning("Playbook missing 'references' field")
    elif not isinstance(playbook["references"], list):
        errors.append("'references' is not a list")
    
    # Check for verification_procedures (optional)
    if "verification_procedures" in playbook and not isinstance(playbook["verification_procedures"], list):
        errors.append("'verification_procedures' is not a list")
    
    # Check for rollback_procedures (optional)
    if "rollback_procedures" in playbook and not isinstance(playbook["rollback_procedures"], list):
        errors.append("'rollback_procedures' is not a list")
    
    return len(errors) == 0


def test_parser():
    """Test the parser with sample responses."""
    print("=" * 60)
    print("PLAYBOOK PARSER TEST")
    print("=" * 60)
    
    # Test 1: Valid JSON response
    print("\n1. Testing valid JSON response:")
    valid_json = '''{
        "playbook": {
            "title": "Test Playbook",
            "cve_id": "CVE-TEST-0001",
            "severity": "High",
            "affected_components": ["test-component"],
            "remediation_steps": [
                {
                    "step_number": 1,
                    "description": "Test step description",
                    "commands": ["command1", "command2"],
                    "verification": "Check logs for success",
                    "evidence_based": true
                }
            ],
            "verification_procedures": ["Verify system logs", "Check monitoring"],
            "rollback_procedures": ["Restore from backup", "Revert configuration"],
            "references": ["https://example.com"]
        }
    }'''
    
    result = parse_playbook_response(valid_json)
    print(f"Parsed OK: {result['parsed_ok']}")
    print(f"Errors: {result['parse_errors']}")
    print(f"Has playbook: {'playbook' in result['parsed_playbook'] if result['parsed_playbook'] else False}")
    
    # Test 2: JSON with markdown fences
    print("\n2. Testing JSON with markdown fences:")
    json_with_fences = '''```json
{
    "playbook": {
        "title": "Fenced Playbook",
        "cve_id": "CVE-TEST-0002",
        "severity": "Medium",
        "affected_components": ["component1", "component2"],
        "remediation_steps": [
            {
                "step_number": 1,
                "description": "Test step description",
                "commands": ["cmd1"],
                "verification": "Verify step 1",
                "evidence_based": false
            }
        ],
        "verification_procedures": ["Verify all steps"],
        "rollback_procedures": ["Rollback plan"],
        "references": ["ref1", "ref2"]
    }
}
```'''
    
    result = parse_playbook_response(json_with_fences)
    print(f"Parsed OK: {result['parsed_ok']}")
    print(f"Errors: {result['parse_errors']}")
    
    # Test 3: Malformed JSON
    print("\n3. Testing malformed JSON:")
    malformed_json = '''{
        "playbook": {
            "title": "Bad Playbook",
            "cve_id": "CVE-TEST-0003",
            "remediation_steps": [
    }'''
    
    result = parse_playbook_response(malformed_json)
    print(f"Parsed OK: {result['parsed_ok']}")
    print(f"Errors: {result['parse_errors']}")
    
    # Test 4: Text with JSON inside
    print("\n4. Testing text with JSON inside:")
    text_with_json = '''Here is the playbook you requested:

{
    "playbook": {
        "title": "Text Playbook",
        "cve_id": "CVE-TEST-0004",
        "remediation_steps": [
            {"step_number": 1, "description": "Step 1"}
        ]
    }
}

Please review and let me know if you need changes.'''
    
    result = parse_playbook_response(text_with_json)
    print(f"Parsed OK: {result['parsed_ok']}")
    print(f"Errors: {result['parse_errors']}")
    
    # Test 5: Empty response
    print("\n5. Testing empty response:")
    result = parse_playbook_response("")
    print(f"Parsed OK: {result['parsed_ok']}")
    print(f"Errors: {result['parse_errors']}")
    
    print("\n" + "=" * 60)
    print("PARSER TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    test_parser()