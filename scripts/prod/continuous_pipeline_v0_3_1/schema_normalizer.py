"""
Schema Normalizer for Continuous Pipeline v0.3.1
Version: v0.3.1

Purpose:
- Transform near-canonical outputs into canonical shape
- Map alternative wrapper names to canonical schema
- Record which mappings were applied
"""

import json
import logging
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger(__name__)


class SchemaNormalizer:
    """
    Normalize alternative schema structures into canonical format.
    """
    
    def __init__(self):
        # Define mapping from alternative field names to canonical names
        self.field_mappings = {
            # Header section mappings
            "vulnerability_info": "header",
            "vulnerability": "header",
            "cve_info": "header",
            "cve_details": "header",
            "info": "header",
            
            # Workflows section mappings
            "remediation_workflows": "workflows",
            "remediation_steps": "workflows",
            "steps": "workflows",
            "procedures": "workflows",
            "actions": "workflows",
            
            # Pre-remediation checks mappings
            "pre_checks": "pre_remediation_checks",
            "prerequisites": "pre_remediation_checks",
            "requirements": "pre_remediation_checks",
            "preparation": "pre_remediation_checks",
            
            # Post-remediation validation mappings
            "post_validation": "post_remediation_validation",
            "validation": "post_remediation_validation",
            "verification": "post_remediation_validation",
            "post_checks": "post_remediation_validation",
            
            # Additional recommendations mappings
            "recommendations": "additional_recommendations",
            "suggestions": "additional_recommendations",
            "best_practices": "additional_recommendations",
            "notes": "additional_recommendations",
            
            # Retrieval metadata mappings
            "metadata": "retrieval_metadata",
            "evidence": "retrieval_metadata",
            "sources": "retrieval_metadata",
            "references": "retrieval_metadata",
        }
        
        # Define canonical schema structure
        self.canonical_sections = [
            "header",
            "pre_remediation_checks",
            "workflows",
            "post_remediation_validation",
            "additional_recommendations",
            "retrieval_metadata"
        ]
    
    def normalize(self, parsed_json: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Normalize parsed JSON into canonical schema.
        
        Args:
            parsed_json: Parsed JSON dictionary
            
        Returns:
            Tuple of (normalized_json, metadata)
        """
        metadata = {
            "normalization_applied": False,
            "mappings_applied": [],
            "missing_canonical_sections": [],
            "extra_sections": [],
            "original_keys": list(parsed_json.keys()),
            "error": None
        }
        
        if not parsed_json or not isinstance(parsed_json, dict):
            metadata["error"] = "Invalid input: empty or non-dict"
            return None, metadata
        
        # Check if already in canonical format
        is_canonical = self._is_canonical_format(parsed_json)
        if is_canonical:
            metadata["normalization_applied"] = False
            metadata["is_already_canonical"] = True
            return parsed_json, metadata
        
        # Start with empty canonical structure
        normalized = {}
        mappings_applied = []
        
        # Map alternative field names to canonical names
        for alt_key, canonical_key in self.field_mappings.items():
            if alt_key in parsed_json:
                normalized[canonical_key] = parsed_json[alt_key]
                mappings_applied.append(f"{alt_key} -> {canonical_key}")
        
        # Also copy any keys that match canonical names directly
        for canonical_key in self.canonical_sections:
            if canonical_key in parsed_json and canonical_key not in normalized:
                normalized[canonical_key] = parsed_json[canonical_key]
        
        # Handle nested structures (e.g., playbook wrapper)
        if "playbook" in parsed_json and isinstance(parsed_json["playbook"], dict):
            # Recursively normalize the nested playbook
            nested_normalized, nested_metadata = self.normalize(parsed_json["playbook"])
            if nested_normalized:
                # Merge nested normalization with current
                for key in self.canonical_sections:
                    if key in nested_normalized and key not in normalized:
                        normalized[key] = nested_normalized[key]
                        mappings_applied.append(f"playbook.{key} -> {key}")
                
                metadata["had_playbook_wrapper"] = True
                metadata["nested_mappings"] = nested_metadata.get("mappings_applied", [])
        
        # Check what we have vs what's canonical
        present_sections = [key for key in self.canonical_sections if key in normalized]
        missing_sections = [key for key in self.canonical_sections if key not in normalized]
        
        metadata["normalization_applied"] = len(mappings_applied) > 0
        metadata["mappings_applied"] = mappings_applied
        metadata["present_canonical_sections"] = present_sections
        metadata["missing_canonical_sections"] = missing_sections
        
        # Copy any extra sections that weren't mapped
        for key, value in parsed_json.items():
            if key not in normalized and key not in self.field_mappings:
                normalized[key] = value
                metadata["extra_sections"].append(key)
        
        # Ensure workflows is a list if present
        if "workflows" in normalized and not isinstance(normalized["workflows"], list):
            if isinstance(normalized["workflows"], dict):
                # Convert single workflow dict to list
                normalized["workflows"] = [normalized["workflows"]]
                metadata["mappings_applied"].append("workflows dict -> list")
            else:
                # Invalid workflows type
                del normalized["workflows"]
                metadata["missing_canonical_sections"].append("workflows")
        
        # Add CVE ID to header if missing but available elsewhere
        if "header" in normalized and isinstance(normalized["header"], dict):
            if "cve_id" not in normalized["header"]:
                # Try to find CVE ID in the data
                cve_id = self._find_cve_id(parsed_json, normalized)
                if cve_id:
                    normalized["header"]["cve_id"] = cve_id
                    metadata["mappings_applied"].append(f"cve_id -> header.cve_id")
        
        return normalized, metadata
    
    def _is_canonical_format(self, data: Dict[str, Any]) -> bool:
        """
        Check if data is already in canonical format.
        
        Args:
            data: Parsed JSON dictionary
            
        Returns:
            True if data matches canonical format
        """
        # Check for all canonical sections
        has_all_sections = all(section in data for section in self.canonical_sections)
        
        if has_all_sections:
            # Additional check: workflows should be a list
            if isinstance(data.get("workflows"), list):
                return True
        
        return False
    
    def _find_cve_id(self, original: Dict[str, Any], normalized: Dict[str, Any]) -> Optional[str]:
        """
        Find CVE ID in the data structure.
        
        Args:
            original: Original parsed JSON
            normalized: Partially normalized JSON
            
        Returns:
            CVE ID string if found, None otherwise
        """
        # Check common CVE ID locations
        locations = [
            # In header
            normalized.get("header", {}).get("cve_id"),
            normalized.get("header", {}).get("cve"),
            normalized.get("header", {}).get("id"),
            
            # Top level
            original.get("cve_id"),
            original.get("cve"),
            original.get("id"),
            
            # In nested structures
            original.get("playbook", {}).get("cve_id"),
            original.get("playbook", {}).get("cve"),
            original.get("playbook", {}).get("id"),
            
            # In vulnerability_info
            original.get("vulnerability_info", {}).get("cve_id"),
            original.get("vulnerability_info", {}).get("cve"),
            original.get("vulnerability_info", {}).get("id"),
        ]
        
        for location in locations:
            if location and isinstance(location, str) and location.upper().startswith("CVE-"):
                return location
        
        return None
    
    def normalize_with_context(self, parsed_json: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize with full context metadata.
        
        Args:
            parsed_json: Parsed JSON dictionary
            
        Returns:
            Dictionary with normalization results and metadata
        """
        normalized_json, metadata = self.normalize(parsed_json)
        
        result = {
            "original_json": parsed_json,
            "normalized_json": normalized_json,
            "metadata": metadata,
            "success": normalized_json is not None
        }
        
        return result
    
    def get_semantic_utility(self, normalized_json: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess semantic utility of normalized JSON.
        
        Args:
            normalized_json: Normalized JSON dictionary
            
        Returns:
            Dictionary with utility assessment
        """
        if not normalized_json or not isinstance(normalized_json, dict):
            return {
                "has_useful_content": False,
                "missing_critical_sections": self.canonical_sections,
                "workflow_count": 0,
                "assessment": "empty"
            }
        
        # Check for critical sections
        critical_sections = ["workflows", "header"]
        present_critical = [section for section in critical_sections if section in normalized_json]
        missing_critical = [section for section in critical_sections if section not in normalized_json]
        
        # Check workflow content
        workflow_count = 0
        if "workflows" in normalized_json and isinstance(normalized_json["workflows"], list):
            workflow_count = len(normalized_json["workflows"])
        
        # Check for placeholder/generic content
        has_generic_content = self._check_for_generic_content(normalized_json)
        
        # Determine utility level
        if len(missing_critical) == 0 and workflow_count > 0 and not has_generic_content:
            assessment = "high_utility"
        elif len(missing_critical) == 0 and workflow_count > 0:
            assessment = "medium_utility"
        elif workflow_count > 0:
            assessment = "partial_utility"
        elif len(present_critical) > 0:
            assessment = "low_utility"
        else:
            assessment = "minimal_utility"
        
        return {
            "has_useful_content": workflow_count > 0 or len(present_critical) > 0,
            "present_critical_sections": present_critical,
            "missing_critical_sections": missing_critical,
            "workflow_count": workflow_count,
            "has_generic_content": has_generic_content,
            "assessment": assessment
        }
    
    def _check_for_generic_content(self, data: Dict[str, Any]) -> bool:
        """
        Check for generic or placeholder content.
        
        Args:
            data: JSON dictionary
            
        Returns:
            True if generic content is detected
        """
        generic_patterns = [
            "TODO", "FIXME", "INSERT", "ADD HERE", "EXAMPLE", "SAMPLE",
            "PLACEHOLDER", "DESCRIBE", "EXPLAIN", "FILL IN", "TBD"
        ]
        
        def check_value(value):
            if isinstance(value, str):
                value_upper = value.upper()
                for pattern in generic_patterns:
                    if pattern in value_upper:
                        return True
            elif isinstance(value, dict):
                for subvalue in value.values():
                    if check_value(subvalue):
                        return True
            elif isinstance(value, list):
                for item in value:
                    if check_value(item):
                        return True
            return False
        
        return check_value(data)