"""
Canonical Schema for Continuous Pipeline v0.2.0
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z

Purpose:
- Define the canonical playbook schema used by Phase 1 runner
- Provide validation and parsing functions
- Ensure schema convergence between pipelines
"""

import json
import re
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CanonicalSchema:
    """
    Canonical schema validator and parser.
    
    This replicates the behavior of src.utils.playbook_parser.PlaybookParser
    but adapted for the continuous pipeline context.
    """
    
    def __init__(self):
        logger.info("CanonicalSchema initialized")
    
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
    
    def _try_json_parse(self, text: str, errors: List[str]) -> Optional[Dict[str, Any]]:
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
        
        # Try to find JSON object in text
        json_patterns = [
            r'\{.*\}',  # Any JSON object
            r'```json\s*(.*?)\s*```',  # Markdown JSON code block
            r'```\s*(.*?)\s*```',  # Any code block
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, text, re.DOTALL)
            for match in matches:
                try:
                    return json.loads(match.strip())
                except json.JSONDecodeError:
                    continue
        
        errors.append(f"Failed to parse JSON: {first_error}")
        return None
    
    def _strip_markdown_fences(self, text: str) -> str:
        """Strip markdown code fences from text."""
        # Remove ```json ... ```
        text = re.sub(r'```json\s*(.*?)\s*```', r'\1', text, flags=re.DOTALL)
        # Remove ``` ... ```
        text = re.sub(r'```\s*(.*?)\s*```', r'\1', text, flags=re.DOTALL)
        # Remove ~~~ ... ~~~
        text = re.sub(r'~~~\s*(.*?)\s*~~~', r'\1', text, flags=re.DOTALL)
        return text.strip()
    
    def _validate_playbook_structure(self, parsed_data: Dict[str, Any], errors: List[str]) -> bool:
        """
        Validate playbook structure against canonical schema.
        
        Args:
            parsed_data: Parsed JSON data
            errors: List to append validation errors to
            
        Returns:
            True if valid, False otherwise
        """
        # Check if it's a playbook object
        if not isinstance(parsed_data, dict):
            errors.append("Root element must be a JSON object")
            return False
        
        # Log diagnostic info about the parsed data
        logger.info(f"Schema validation diagnostic - Parsed data keys: {list(parsed_data.keys())}")
        
        # Check if it has playbook wrapper
        has_playbook_wrapper = 'playbook' in parsed_data and isinstance(parsed_data['playbook'], dict)
        logger.info(f"Schema validation diagnostic - Has playbook wrapper: {has_playbook_wrapper}")
        
        # Check if it has canonical keys directly
        canonical_keys = ['header', 'pre_remediation_checks', 'workflows', 'post_remediation_validation', 'additional_recommendations', 'retrieval_metadata']
        has_canonical_keys = all(key in parsed_data for key in canonical_keys)
        logger.info(f"Schema validation diagnostic - Has canonical keys directly: {has_canonical_keys}")
        
        # Normalize the payload first
        normalized = self._normalize_playbook_payload(parsed_data)
        if normalized is None:
            errors.append("Payload does not match canonical schema: missing required top-level keys")
            logger.info(f"Schema validation diagnostic - Failed to normalize payload")
            return False
        
        logger.info(f"Schema validation diagnostic - Normalized payload keys: {list(normalized.keys())}")
        
        # Validate canonical structure
        return self._validate_canonical_content(normalized, errors)
    
    def _normalize_playbook_payload(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize playbook payload to canonical format.
        
        Args:
            payload: Parsed JSON payload
            
        Returns:
            Normalized canonical payload or None if invalid
        """
        # Check if payload has "playbook" wrapper (backward compatibility)
        if 'playbook' in payload and isinstance(payload['playbook'], dict):
            # Unwrap the playbook
            canonical = payload['playbook']
        else:
            # Use payload directly
            canonical = payload
        
        # Check if this matches canonical top-level keys
        canonical_required_keys = [
            'header',
            'pre_remediation_checks',
            'workflows',
            'post_remediation_validation',
            'additional_recommendations',
            'retrieval_metadata'
        ]
        
        # Check if all required canonical keys are present
        for key in canonical_required_keys:
            if key not in canonical:
                return None
        
        return canonical
    
    def _validate_canonical_content(self, canonical: Dict[str, Any], errors: List[str]) -> bool:
        """
        Validate canonical content against required fields.
        
        Args:
            canonical: Canonical dictionary
            errors: List to append validation errors to
            
        Returns:
            True if valid, False otherwise
        """
        # Validate header
        if 'header' not in canonical:
            errors.append("Missing 'header' section")
            return False
        
        header = canonical['header']
        if not isinstance(header, dict):
            errors.append("'header' must be a JSON object")
            return False
        
        header_required = ['cve_id', 'title', 'vendor', 'product', 'severity', 'vulnerability_type', 'description']
        for field in header_required:
            if field not in header:
                errors.append(f"Missing required header field: '{field}'")
            elif not header[field]:
                errors.append(f"Header field '{field}' is empty")
        
        # Validate pre_remediation_checks
        if 'pre_remediation_checks' not in canonical:
            errors.append("Missing 'pre_remediation_checks' section")
        elif not isinstance(canonical['pre_remediation_checks'], dict):
            errors.append("'pre_remediation_checks' must be a JSON object")
        
        # Validate workflows
        if 'workflows' not in canonical:
            errors.append("Missing 'workflows' section")
        elif not isinstance(canonical['workflows'], list):
            errors.append("'workflows' must be a list")
        elif len(canonical['workflows']) == 0:
            errors.append("'workflows' must contain at least one workflow")
        
        # Validate post_remediation_validation
        if 'post_remediation_validation' not in canonical:
            errors.append("Missing 'post_remediation_validation' section")
        elif not isinstance(canonical['post_remediation_validation'], dict):
            errors.append("'post_remediation_validation' must be a JSON object")
        
        # Validate additional_recommendations
        if 'additional_recommendations' not in canonical:
            errors.append("Missing 'additional_recommendations' section")
        elif not isinstance(canonical['additional_recommendations'], list):
            errors.append("'additional_recommendations' must be a list")
        
        # Validate retrieval_metadata
        if 'retrieval_metadata' not in canonical:
            errors.append("Missing 'retrieval_metadata' section")
        elif not isinstance(canonical['retrieval_metadata'], dict):
            errors.append("'retrieval_metadata' must be a JSON object")
        
        return len(errors) == 0
    
    def normalize_playbook(self, playbook: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize playbook to canonical format.
        
        Args:
            playbook: Playbook dictionary (may be in legacy format)
            
        Returns:
            Normalized playbook in canonical format
        """
        # First try to normalize to canonical format
        canonical = self._normalize_playbook_payload(playbook)
        if canonical is not None:
            # Already in canonical format
            return canonical
        
        # If not canonical, check if it's old wrapped format
        if 'playbook' in playbook and isinstance(playbook['playbook'], dict):
            # Return as-is for backward compatibility
            return playbook
        
        # Otherwise, wrap in canonical format for backward compatibility
        return {
            'playbook': playbook
        }
    
    def get_schema_template(self) -> Dict[str, Any]:
        """
        Get canonical schema template.
        
        Returns:
            Schema template dictionary
        """
        return {
            "header": {
                "title": "Remediation Playbook for CVE-XXXX-XXXX",
                "cve_id": "CVE-YYYY-NNNNN",
                "vendor": "Vendor name",
                "product": "Product name",
                "severity": "Critical/High/Medium/Low",
                "vulnerability_type": "Type of vulnerability",
                "description": "Brief description",
                "affected_versions": ["version range"],
                "fixed_versions": ["fixed version"],
                "affected_platforms": ["Linux", "Windows"],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN"]
            },
            "pre_remediation_checks": {
                "required_checks": [
                    {
                        "check_id": "check_1",
                        "description": "Verify system backup exists",
                        "commands": ["command to check"],
                        "expected_result": "Backup verification successful"
                    }
                ],
                "backup_steps": [
                    {
                        "step_id": "backup_1",
                        "description": "Create system backup",
                        "commands": ["backup command"],
                        "verification": "Backup created successfully"
                    }
                ],
                "prerequisites": ["Required tools", "Permissions"]
            },
            "workflows": [
                {
                    "workflow_id": "workflow_1",
                    "workflow_name": "Repository Update Workflow",
                    "workflow_type": "repository_update",
                    "applicability_conditions": {
                        "os_family": ["Linux"],
                        "package_managers": ["apt", "yum"],
                        "environments": ["production", "staging"]
                    },
                    "prerequisites": ["Package manager access"],
                    "steps": [
                        {
                            "step_number": 1,
                            "title": "Update package repositories",
                            "description": "Update package repository cache",
                            "commands": ["sudo apt update"],
                            "target_os_or_platform": "Linux/Ubuntu",
                            "expected_result": "Repository cache updated",
                            "verification": "Check update completed",
                            "rollback_hint": "No rollback needed",
                            "evidence_based": True
                        }
                    ]
                }
            ],
            "post_remediation_validation": {
                "validation_steps": [
                    {
                        "step_id": "validation_1",
                        "description": "Verify patch applied",
                        "commands": ["version check command"],
                        "expected_outcomes": ["Version matches fixed version"]
                    }
                ],
                "testing_procedures": [
                    {
                        "test_id": "test_1",
                        "description": "Test functionality",
                        "commands": ["test command"],
                        "pass_criteria": "All tests pass"
                    }
                ]
            },
            "additional_recommendations": [
                {
                    "recommendation_id": "rec_1",
                    "category": "security_hardening",
                    "description": "Additional security recommendations",
                    "priority": "high",
                    "implementation_guidance": "Implementation steps"
                }
            ],
            "retrieval_metadata": {
                "decision": "strong",
                "evidence_count": 5,
                "source_indexes": ["nvd", "vendor_advisories"],
                "generation_timestamp": "2026-04-17T00:00:00Z"
            }
        }
    
    def validate_and_normalize(self, raw_response: str) -> Tuple[bool, Optional[Dict[str, Any]], List[str]]:
        """
        Validate and normalize LLM response.
        
        Args:
            raw_response: Raw LLM response text
            
        Returns:
            Tuple of (is_valid, normalized_playbook, errors)
        """
        parse_result = self.parse_playbook_response(raw_response)
        
        if not parse_result['parsed_ok']:
            return False, None, parse_result['parse_errors']
        
        # Normalize to canonical format
        normalized = self.normalize_playbook(parse_result['parsed_playbook'])
        
        return True, normalized, []