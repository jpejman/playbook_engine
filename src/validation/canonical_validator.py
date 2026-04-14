#!/usr/bin/env python3
"""
Canonical Schema Validator for Playbook Engine
Version: v0.1.0
Timestamp: 2026-04-09

Purpose:
- Validate playbook output matches canonical schema
- Reject mock/test outputs in production
- Enforce canonical output shape before storage
"""

import json
import re
from typing import Dict, Any, List, Optional, Tuple


class CanonicalValidator:
    """Validator for canonical playbook schema."""
    
    # Required top-level fields for canonical schema
    REQUIRED_TOP_LEVEL_FIELDS = [
        "title",
        "cve_id", 
        "vendor",
        "product",
        "severity",
        "vulnerability_type",
        "description",
        "affected_versions",
        "fixed_versions",
        "affected_platforms",
        "references",
        "retrieval_metadata",
        "pre_remediation_checks",
        "workflows",
        "post_remediation_validation",
        "additional_recommendations"
    ]
    
    # Obsolete keys that indicate mock/legacy schema
    OBSOLETE_KEYS = [
        "affected_components",
        "remediation_steps",
        "verification_procedures",
        "rollback_procedures"
    ]
    
    # Mock/test indicators
    MOCK_INDICATORS = {
        "prompt": ["mock prompt", "test prompt", "sample prompt"],
        "model": ["test-model", "mock-model", "sample-model"],
        "content": ["mock response", "test response", "sample response"]
    }
    
    # Placeholder content indicators for production validation
    PLACEHOLDER_INDICATORS = {
        "vendor": ["test vendor", "example vendor", "demo vendor", "placeholder vendor"],
        "product": ["test product", "example product", "demo product", "placeholder product", "test-package"],
        "description": ["test vulnerability", "for demonstration", "example description", "placeholder description"],
        "versions": ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"],  # Generic version patterns
        "cve_references": ["cve-test", "example.com", "test-cve", "placeholder-cve"],
        "generic_remediation": ["update to latest version", "upgrade software", "apply patches"]
    }
    
    def __init__(self, production_mode: bool = True):
        self.production_mode = production_mode
        
    def validate_canonical_schema(self, playbook_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate playbook matches canonical schema.
        
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Check if data is nested under "playbook" key (obsolete schema)
        if "playbook" in playbook_data:
            errors.append("Playbook data is nested under 'playbook' key (obsolete schema)")
            # Check nested structure for additional validation
            nested_data = playbook_data.get("playbook", {})
        else:
            nested_data = playbook_data
        
        # Check for obsolete keys
        for obsolete_key in self.OBSOLETE_KEYS:
            if obsolete_key in nested_data:
                errors.append(f"Contains obsolete key: '{obsolete_key}'")
        
        # Check required top-level fields
        for field in self.REQUIRED_TOP_LEVEL_FIELDS:
            if field not in playbook_data:
                errors.append(f"Missing required field: '{field}'")
        
        # Check workflows array
        if "workflows" in playbook_data:
            workflows = playbook_data["workflows"]
            if not isinstance(workflows, list):
                errors.append("'workflows' must be an array")
            elif len(workflows) == 0:
                errors.append("'workflows' array must not be empty")
            else:
                # Validate workflow structure
                for i, workflow in enumerate(workflows):
                    if not isinstance(workflow, dict):
                        errors.append(f"Workflow {i} must be a dictionary")
                        continue
                    
                    # Check required workflow fields
                    workflow_required = ["workflow_id", "workflow_name", "workflow_type", "steps"]
                    for field in workflow_required:
                        if field not in workflow:
                            errors.append(f"Workflow {i} missing required field: '{field}'")
                    
                    # Check steps
                    if "steps" in workflow:
                        steps = workflow["steps"]
                        if not isinstance(steps, list):
                            errors.append(f"Workflow {i} 'steps' must be an array")
                        elif len(steps) == 0:
                            errors.append(f"Workflow {i} 'steps' array must not be empty")
                        else:
                            # Validate step structure
                            for j, step in enumerate(steps):
                                if not isinstance(step, dict):
                                    errors.append(f"Workflow {i}, Step {j} must be a dictionary")
                                    continue
                                
                                step_required = ["step_number", "title", "description", "commands", 
                                               "target_os_or_platform", "expected_result", "verification"]
                                for field in step_required:
                                    if field not in step:
                                        errors.append(f"Workflow {i}, Step {j} missing required field: '{field}'")
        
        # Check retrieval_metadata
        if "retrieval_metadata" in playbook_data:
            metadata = playbook_data["retrieval_metadata"]
            if not isinstance(metadata, dict):
                errors.append("'retrieval_metadata' must be a dictionary")
            else:
                metadata_required = ["decision", "evidence_count", "source_indexes", "generation_timestamp"]
                for field in metadata_required:
                    if field not in metadata:
                        errors.append(f"'retrieval_metadata' missing required field: '{field}'")
        
        return len(errors) == 0, errors
    
    def detect_mock_output(self, prompt: Optional[str] = None, model: Optional[str] = None, 
                          response: Optional[Dict] = None) -> Tuple[bool, List[str]]:
        """
        Detect mock/test outputs.
        
        Returns:
            Tuple of (is_mock, warning_messages)
        """
        warnings = []
        is_mock = False
        
        # Check prompt for mock indicators
        if prompt:
            prompt_lower = prompt.lower()
            for indicator in self.MOCK_INDICATORS["prompt"]:
                if indicator in prompt_lower:
                    warnings.append(f"Prompt contains mock indicator: '{indicator}'")
                    is_mock = True
        
        # Check model for mock indicators
        if model:
            model_lower = model.lower()
            for indicator in self.MOCK_INDICATORS["model"]:
                if indicator in model_lower:
                    warnings.append(f"Model contains mock indicator: '{indicator}'")
                    is_mock = True
        
        # Check response content for mock indicators
        if response:
            response_str = json.dumps(response).lower()
            for indicator in self.MOCK_INDICATORS["content"]:
                if indicator in response_str:
                    warnings.append(f"Response contains mock indicator: '{indicator}'")
                    is_mock = True
        
        return is_mock, warnings
    
    def detect_placeholder_content(self, playbook_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Detect placeholder/synthetic content in playbook.
        
        Returns:
            Tuple of (has_placeholder, warning_messages)
        """
        warnings = []
        has_placeholder = False
        
        if not playbook_data:
            return False, warnings
        
        # Extract playbook from nested structure if needed
        data = playbook_data.get("playbook", playbook_data) if "playbook" in playbook_data else playbook_data
        
        # Check vendor field
        vendor = str(data.get("vendor", "")).lower()
        for indicator in self.PLACEHOLDER_INDICATORS["vendor"]:
            if indicator in vendor:
                warnings.append(f"Vendor field contains placeholder: '{data.get('vendor')}'")
                has_placeholder = True
        
        # Check product field
        product = str(data.get("product", "")).lower()
        for indicator in self.PLACEHOLDER_INDICATORS["product"]:
            if indicator in product:
                warnings.append(f"Product field contains placeholder: '{data.get('product')}'")
                has_placeholder = True
        
        # Check description field
        description = str(data.get("description", "")).lower()
        for indicator in self.PLACEHOLDER_INDICATORS["description"]:
            if indicator in description:
                warnings.append(f"Description contains placeholder phrase: '{indicator}'")
                has_placeholder = True
        
        # Check affected_versions and fixed_versions
        for version_field in ["affected_versions", "fixed_versions"]:
            if version_field in data and isinstance(data[version_field], list):
                for version in data[version_field]:
                    version_str = str(version).lower()
                    for indicator in self.PLACEHOLDER_INDICATORS["versions"]:
                        if version_str == indicator:
                            warnings.append(f"Version {version} in {version_field} appears generic/placeholder")
                            has_placeholder = True
        
        # Check references
        if "references" in data and isinstance(data["references"], list):
            for ref in data["references"]:
                ref_str = str(ref).lower()
                for indicator in self.PLACEHOLDER_INDICATORS["cve_references"]:
                    if indicator in ref_str:
                        warnings.append(f"Reference contains placeholder: '{ref}'")
                        has_placeholder = True
        
        # Check workflows for generic remediation
        if "workflows" in data and isinstance(data["workflows"], list):
            workflows_str = json.dumps(data["workflows"]).lower()
            for indicator in self.PLACEHOLDER_INDICATORS["generic_remediation"]:
                if indicator in workflows_str:
                    warnings.append(f"Contains generic remediation phrase: '{indicator}'")
                    has_placeholder = True
        
        return has_placeholder, warnings
    
    def validate_for_production(self, prompt: str, model: str, playbook_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Comprehensive validation for production mode.
        
        Returns:
            Tuple of (is_valid, error_messages)
        """
        all_errors = []
        
        # 1. Detect mock outputs
        is_mock, mock_warnings = self.detect_mock_output(prompt, model, playbook_data)
        if is_mock and self.production_mode:
            all_errors.append("Mock/test output detected in production mode")
            all_errors.extend(mock_warnings)
        
        # 2. Detect placeholder content
        has_placeholder, placeholder_warnings = self.detect_placeholder_content(playbook_data)
        if has_placeholder and self.production_mode:
            all_errors.append("Placeholder/synthetic content detected in production mode")
            all_errors.extend(placeholder_warnings)
        
        # 3. Validate canonical schema
        is_canonical, schema_errors = self.validate_canonical_schema(playbook_data)
        if not is_canonical:
            all_errors.extend(schema_errors)
        
        # 4. Additional production checks
        if self.production_mode:
            # Check for generic remediation
            if self._contains_generic_remediation(playbook_data):
                all_errors.append("Contains generic remediation (e.g., 'update to latest version')")
            
            # Check for evidence-based steps
            if not self._has_evidence_based_steps(playbook_data):
                all_errors.append("No evidence-based steps marked")
        
        return len(all_errors) == 0, all_errors
    
    def _contains_generic_remediation(self, playbook_data: Dict[str, Any]) -> bool:
        """Check for generic remediation phrases."""
        generic_phrases = [
            "update to latest version",
            "upgrade to newest version", 
            "apply latest patches",
            "install security updates",
            "update software"
        ]
        
        playbook_str = json.dumps(playbook_data).lower()
        for phrase in generic_phrases:
            if phrase in playbook_str:
                return True
        return False
    
    def _has_evidence_based_steps(self, playbook_data: Dict[str, Any]) -> bool:
        """Check if any steps are marked as evidence_based."""
        if "workflows" not in playbook_data:
            return False
        
        workflows = playbook_data["workflows"]
        if not isinstance(workflows, list):
            return False
        
        for workflow in workflows:
            if isinstance(workflow, dict) and "steps" in workflow:
                steps = workflow["steps"]
                if isinstance(steps, list):
                    for step in steps:
                        if isinstance(step, dict) and step.get("evidence_based") is True:
                            return True
        return False
    
    def normalize_to_canonical(self, legacy_playbook: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Attempt to normalize legacy playbook to canonical schema.
        
        Returns:
            Normalized canonical playbook or None if normalization fails
        """
        try:
            # Extract playbook from nested structure
            if "playbook" in legacy_playbook:
                legacy_data = legacy_playbook["playbook"]
            else:
                legacy_data = legacy_playbook
            
            # Build canonical structure
            canonical = {
                "title": legacy_data.get("title", ""),
                "cve_id": legacy_data.get("cve_id", ""),
                "vendor": "",
                "product": "",
                "severity": legacy_data.get("severity", ""),
                "vulnerability_type": "",
                "description": "",
                "affected_versions": [],
                "fixed_versions": [],
                "affected_platforms": [],
                "references": legacy_data.get("references", []),
                "retrieval_metadata": {
                    "decision": "none",
                    "evidence_count": 0,
                    "source_indexes": [],
                    "generation_timestamp": ""
                },
                "pre_remediation_checks": {
                    "required_checks": [],
                    "backup_steps": [],
                    "prerequisites": []
                },
                "workflows": [],
                "post_remediation_validation": {
                    "validation_steps": [],
                    "testing_procedures": []
                },
                "additional_recommendations": []
            }
            
            # Convert remediation_steps to workflows if present
            if "remediation_steps" in legacy_data:
                steps = legacy_data["remediation_steps"]
                if isinstance(steps, list) and len(steps) > 0:
                    workflow = {
                        "workflow_id": "workflow_1",
                        "workflow_name": "Remediation Workflow",
                        "workflow_type": "other",
                        "applicability_conditions": {
                            "os_family": [],
                            "package_managers": [],
                            "environments": ["production", "staging", "development"]
                        },
                        "prerequisites": [],
                        "steps": []
                    }
                    
                    for i, step in enumerate(steps):
                        if isinstance(step, dict):
                            canonical_step = {
                                "step_number": i + 1,
                                "title": step.get("description", f"Step {i+1}")[:100],
                                "description": step.get("description", ""),
                                "commands": step.get("commands", []),
                                "target_os_or_platform": "",
                                "expected_result": "",
                                "verification": step.get("verification", ""),
                                "rollback_hint": "",
                                "evidence_based": False
                            }
                            workflow["steps"].append(canonical_step)
                    
                    if workflow["steps"]:
                        canonical["workflows"].append(workflow)
            
            return canonical
            
        except Exception as e:
            print(f"Normalization failed: {e}")
            return None


def validate_playbook_canonical(playbook_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Convenience function for validating canonical schema."""
    validator = CanonicalValidator()
    return validator.validate_canonical_schema(playbook_data)


def detect_mock_playbook(prompt: str, model: str, response: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Convenience function for detecting mock outputs."""
    validator = CanonicalValidator()
    is_mock, mock_warnings = validator.detect_mock_output(prompt, model, response)
    has_placeholder, placeholder_warnings = validator.detect_placeholder_content(response)
    
    all_warnings = mock_warnings + placeholder_warnings
    is_problematic = is_mock or has_placeholder
    
    return is_problematic, all_warnings