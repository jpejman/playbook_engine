#!/usr/bin/env python3
"""
Storage Guard for Playbook Engine
Version: v0.1.0
Timestamp: 2026-04-09

Purpose:
- Validate data before storage in generation_runs
- Reject mock/test outputs in production
- Enforce canonical schema before marking as completed
"""

import json
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime

from .canonical_validator import CanonicalValidator


class StorageGuard:
    """Guard for database storage operations."""
    
    def __init__(self, production_mode: bool = True):
        self.production_mode = production_mode
        self.validator = CanonicalValidator(production_mode)
        
    def validate_generation_run(self, 
                               cve_id: str,
                               prompt: str,
                               model: str,
                               response: Dict[str, Any],
                               template_version_id: Optional[int] = None,
                               db_client = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate generation run before storage.
        
        Args:
            cve_id: CVE identifier
            prompt: Rendered prompt
            model: Model name used
            response: Parsed response from LLM
            template_version_id: Prompt template version ID
            db_client: Database client for additional validation
            
        Returns:
            Tuple of (is_valid, validation_result)
        """
        validation_result = {
            "is_valid": False,
            "errors": [],
            "warnings": [],
            "is_mock": False,
            "is_canonical": False,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # 1. Check for mock/test indicators
        is_mock, mock_warnings = self.validator.detect_mock_output(prompt, model, response)
        if is_mock:
            validation_result["is_mock"] = True
            validation_result["warnings"].extend(mock_warnings)
            
            if self.production_mode:
                validation_result["errors"].append("Mock/test output detected in production mode")
        
        # 2. Check for placeholder content
        has_placeholder, placeholder_warnings = self.validator.detect_placeholder_content(response)
        if has_placeholder:
            validation_result["has_placeholder"] = True
            validation_result["warnings"].extend(placeholder_warnings)
            
            if self.production_mode:
                validation_result["errors"].append("Placeholder/synthetic content detected in production mode")
        
        # 2. Validate canonical schema
        is_canonical, schema_errors = self.validator.validate_canonical_schema(response)
        validation_result["is_canonical"] = is_canonical
        if not is_canonical:
            validation_result["errors"].extend(schema_errors)
        
        # 3. Validate prompt template (if db_client provided)
        if db_client and template_version_id:
            template_valid, template_errors = self._validate_prompt_template(
                template_version_id, db_client
            )
            if not template_valid:
                validation_result["errors"].extend(template_errors)
        
        # 4. Validate model is production model
        if self.production_mode:
            model_valid, model_errors = self._validate_production_model(model)
            if not model_valid:
                validation_result["errors"].extend(model_errors)
        
        # 5. Check CVE ID consistency
        if "cve_id" in response:
            response_cve = response.get("cve_id")
            if isinstance(response, dict) and "playbook" in response:
                response_cve = response["playbook"].get("cve_id", "")
            
            if response_cve and response_cve != cve_id:
                validation_result["errors"].append(
                    f"CVE ID mismatch: prompt={cve_id}, response={response_cve}"
                )
        
        # Determine overall validity
        validation_result["is_valid"] = len(validation_result["errors"]) == 0
        
        return validation_result["is_valid"], validation_result
    
    def _validate_prompt_template(self, template_version_id: int, db_client) -> Tuple[bool, List[str]]:
        """Validate prompt template is canonical."""
        errors = []
        
        try:
            # Fetch template details
            template = db_client.fetch_one(
                """
                SELECT v.version, v.system_block, t.name
                FROM prompt_template_versions v
                JOIN prompt_templates t ON v.template_id = t.id
                WHERE v.id = %s
                """,
                (template_version_id,)
            )
            
            if not template:
                errors.append(f"Template version {template_version_id} not found")
                return False, errors
            
            # Check if template is canonical
            system_block = template["system_block"] or ""
            template_name = template["name"] or ""
            
            is_canonical = (
                "canonical" in system_block.lower() or 
                "Group 6.6" in system_block or
                "canonical" in template_name.lower()
            )
            
            if not is_canonical and self.production_mode:
                errors.append(f"Template {template_name} v{template['version']} is not canonical")
            
            return is_canonical, errors
            
        except Exception as e:
            errors.append(f"Error validating template: {e}")
            return False, errors
    
    def _validate_production_model(self, model: str) -> Tuple[bool, List[str]]:
        """Validate model is a production model."""
        errors = []
        
        # List of known test/mock models
        test_models = ["test-model", "mock-model", "sample-model", "dummy-model"]
        
        model_lower = model.lower()
        for test_model in test_models:
            if test_model in model_lower:
                errors.append(f"Model '{model}' appears to be a test/mock model")
                return False, errors
        
        # Check for production model patterns
        production_patterns = ["gpt-", "claude-", "llama-", "mistral-", "gemini-"]
        has_production_pattern = any(pattern in model_lower for pattern in production_patterns)
        
        if not has_production_pattern:
            errors.append(f"Model '{model}' does not match known production model patterns")
        
        return has_production_pattern, errors
    
    def create_rejected_generation_run(self, 
                                      cve_id: str,
                                      prompt: str,
                                      model: str,
                                      response: Dict[str, Any],
                                      validation_result: Dict[str, Any],
                                      db_client) -> Optional[int]:
        """
        Create a rejected generation run with validation errors.
        
        Returns:
            Generation run ID or None if creation failed
        """
        try:
            # Create error response
            error_response = {
                "validation_error": True,
                "original_response": response,
                "validation_result": validation_result,
                "rejected_at": datetime.utcnow().isoformat()
            }
            
            # Insert as failed generation run
            result = db_client.execute(
                """
                INSERT INTO generation_runs (
                    cve_id, prompt, response, model, status, created_at
                )
                VALUES (%s, %s, %s, %s, %s, NOW())
                RETURNING id
                """,
                (
                    cve_id,
                    prompt,
                    json.dumps(error_response),
                    model,
                    "rejected"
                ),
                fetch=True
            )
            
            if result:
                print(f"Created rejected generation run ID: {result}")
                return result
            else:
                print("Failed to create rejected generation run")
                return None
                
        except Exception as e:
            print(f"Error creating rejected generation run: {e}")
            return None
    
    def enforce_storage_guard(self, 
                             cve_id: str,
                             prompt: str,
                             model: str,
                             response: Dict[str, Any],
                             template_version_id: Optional[int] = None,
                             db_client = None) -> Tuple[bool, Optional[int], Dict[str, Any]]:
        """
        Enforce storage guard with comprehensive validation.
        
        Returns:
            Tuple of (should_store, generation_run_id, validation_result)
            If should_store is False, generation_run_id may be a rejected run ID
        """
        # Validate the generation run
        is_valid, validation_result = self.validate_generation_run(
            cve_id, prompt, model, response, template_version_id, db_client
        )
        
        if is_valid:
            # Valid for storage
            return True, None, validation_result
        else:
            # Invalid - create rejected run if in production mode
            print(f"Storage guard rejected generation run for {cve_id}")
            print(f"Errors: {validation_result['errors']}")
            
            if self.production_mode and db_client:
                rejected_id = self.create_rejected_generation_run(
                    cve_id, prompt, model, response, validation_result, db_client
                )
                return False, rejected_id, validation_result
            else:
                return False, None, validation_result


# Convenience functions
def create_storage_guard(production_mode: bool = True) -> StorageGuard:
    """Create a storage guard instance."""
    return StorageGuard(production_mode)