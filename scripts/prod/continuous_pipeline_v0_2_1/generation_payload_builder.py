"""
Generation Payload Builder for Continuous Pipeline v0.2.1
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z

Purpose:
- Build complete generation payload for LLM
- Integrate canonical prompt builder, schema, and evidence
- Provide debug output for validation
"""

import json
import logging
from typing import Dict, Any, Optional, Tuple
from .canonical_prompt_builder import CanonicalPromptBuilder
from .canonical_schema import CanonicalSchema
from .evidence_packager import EvidencePackager

logger = logging.getLogger(__name__)


class GenerationPayloadBuilder:
    """
    Generation payload builder for continuous pipeline.
    
    Integrates all canonical components to build complete generation payload.
    """
    
    def __init__(self, db_client, opensearch_client):
        self.db = db_client
        self.os = opensearch_client
        self.prompt_builder = CanonicalPromptBuilder(db_client)
        self.schema = CanonicalSchema()
        self.evidence_packager = EvidencePackager(db_client, opensearch_client)
        logger.info("GenerationPayloadBuilder initialized")
    
    def build_generation_payload(self, cve_id: str) -> Dict[str, Any]:
        """
        Build complete generation payload for CVE.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Generation payload dictionary
        """
        logger.info(f"Building generation payload for {cve_id}")
        
        # Fetch CVE from OpenSearch
        cve_doc = self.os.fetch_cve(cve_id)
        if not cve_doc:
            raise RuntimeError(f"Failed to fetch CVE {cve_id} from OpenSearch")
        
        # Package evidence
        evidence_package = self.evidence_packager.package_evidence(cve_id, cve_doc)
        
        # Build canonical prompt
        prompt = self.prompt_builder.build_prompt(
            cve_id=cve_id,
            cve_doc=cve_doc,
            evidence_items=evidence_package.get("retrieved_evidence", [])
        )
        
        # Build payload
        payload = {
            "cve_id": cve_id,
            "cve_doc": cve_doc,
            "evidence_package": evidence_package,
            "prompt": prompt,
            "debug_info": self._build_debug_info(cve_id, cve_doc, evidence_package, prompt)
        }
        
        logger.info(f"Generation payload built for {cve_id}")
        logger.debug(f"Payload debug info: {json.dumps(payload['debug_info'], indent=2)}")
        
        return payload
    
    def _build_debug_info(self, cve_id: str, cve_doc: Dict[str, Any], 
                         evidence_package: Dict[str, Any], prompt: str) -> Dict[str, Any]:
        """Build debug information for payload."""
        schema_template = self.schema.get_schema_template()
        # Get top-level keys from canonical schema (not from nested "playbook" key)
        top_level_keys = list(schema_template.keys())
        
        return {
            "prompt_builder_selected": "CanonicalPromptBuilder",
            "schema_module_selected": "CanonicalSchema",
            "prompt_length": len(prompt),
            "evidence_count": evidence_package.get("evidence_count", 0),
            "retrieval_decision": evidence_package.get("retrieval_decision", "unknown"),
            "source_indexes": evidence_package.get("source_indexes", []),
            "cve_fields_present": list(cve_doc.keys()),
            "top_level_schema_keys": top_level_keys,
            "validation_requirements": [
                "header section present",
                "pre_remediation_checks section present",
                "workflows section present with at least one workflow",
                "post_remediation_validation section present",
                "additional_recommendations section present",
                "retrieval_metadata section present",
                "valid JSON structure"
            ]
        }
    
    def validate_response(self, raw_response: str) -> Tuple[bool, Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Validate LLM response against canonical schema.
        
        Args:
            raw_response: Raw LLM response text
            
        Returns:
            Tuple of (is_valid, normalized_playbook, validation_result)
        """
        validation_result = {
            "validation_passed": False,
            "errors": [],
            "warnings": [],
            "schema_compliance": {},
            "debug_info": {}
        }
        
        # Parse and validate
        is_valid, normalized_playbook, errors = self.schema.validate_and_normalize(raw_response)
        
        validation_result["validation_passed"] = is_valid
        validation_result["errors"] = errors
        
        if is_valid and normalized_playbook:
            # Check schema compliance for canonical format
            # Determine if it's canonical format or wrapped format
            is_canonical_format = all(key in normalized_playbook for key in [
                'header', 'pre_remediation_checks', 'workflows', 
                'post_remediation_validation', 'additional_recommendations', 'retrieval_metadata'
            ])
            
            if is_canonical_format:
                # It's already in canonical format
                canonical = normalized_playbook
                validation_result["schema_compliance"] = {
                    "is_canonical_format": True,
                    "has_header": "header" in canonical,
                    "has_pre_remediation_checks": "pre_remediation_checks" in canonical,
                    "has_workflows": "workflows" in canonical and isinstance(canonical["workflows"], list) and len(canonical["workflows"]) > 0,
                    "has_post_remediation_validation": "post_remediation_validation" in canonical,
                    "has_additional_recommendations": "additional_recommendations" in canonical,
                    "has_retrieval_metadata": "retrieval_metadata" in canonical,
                    "has_cve_id_in_header": "cve_id" in canonical.get("header", {})
                }
                
                # Check for generic/placeholder content in canonical sections
                validation_result["warnings"] = self._check_for_generic_content_canonical(canonical)
                
                # Build debug info
                validation_result["debug_info"] = {
                    "response_length": len(raw_response),
                    "canonical_keys": list(canonical.keys()),
                    "normalized_format": "canonical",
                    "workflow_count": len(canonical.get("workflows", [])),
                    "header_cve_id": canonical.get("header", {}).get("cve_id", "missing")
                }
            else:
                # It's in wrapped or legacy format
                playbook = normalized_playbook.get("playbook", normalized_playbook)
                validation_result["schema_compliance"] = {
                    "is_canonical_format": False,
                    "has_playbook_key": "playbook" in normalized_playbook,
                    "has_cve_id": "cve_id" in playbook,
                    "has_summary": "summary" in playbook,
                    "has_impact": "impact" in playbook,
                    "has_detection": "detection" in playbook,
                    "has_remediation_steps": "remediation_steps" in playbook,
                    "has_validation_steps": "validation_steps" in playbook,
                    "has_rollback_steps": "rollback_steps" in playbook,
                    "has_references": "references" in playbook
                }
                
                # Check for generic/placeholder content
                validation_result["warnings"] = self._check_for_generic_content(playbook)
                
                # Build debug info
                validation_result["debug_info"] = {
                    "response_length": len(raw_response),
                    "playbook_keys": list(playbook.keys()),
                    "normalized_format": "wrapped" if "playbook" in normalized_playbook else "legacy"
                }
        
        return is_valid, normalized_playbook, validation_result
    
    def _check_for_generic_content(self, playbook: Dict[str, Any]) -> List[str]:
        """Check for generic or placeholder content in playbook."""
        warnings = []
        generic_patterns = [
            "TODO", "FIXME", "INSERT", "ADD HERE", "EXAMPLE", "SAMPLE",
            "PLACEHOLDER", "DESCRIBE", "EXPLAIN", "FILL IN"
        ]
        
        for field, value in playbook.items():
            if isinstance(value, str):
                value_upper = value.upper()
                for pattern in generic_patterns:
                    if pattern in value_upper:
                        warnings.append(f"Generic content detected in '{field}': contains '{pattern}'")
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        item_upper = item.upper()
                        for pattern in generic_patterns:
                            if pattern in item_upper:
                                warnings.append(f"Generic content detected in '{field}[{i}]': contains '{pattern}'")
        
        return warnings
    
    def _check_for_generic_content_canonical(self, canonical: Dict[str, Any]) -> List[str]:
        """Check for generic or placeholder content in canonical playbook."""
        warnings = []
        generic_patterns = [
            "TODO", "FIXME", "INSERT", "ADD HERE", "EXAMPLE", "SAMPLE",
            "PLACEHOLDER", "DESCRIBE", "EXPLAIN", "FILL IN"
        ]
        
        def check_value(value, path):
            if isinstance(value, str):
                value_upper = value.upper()
                for pattern in generic_patterns:
                    if pattern in value_upper:
                        warnings.append(f"Generic content detected in '{path}': contains '{pattern}'")
            elif isinstance(value, dict):
                for k, v in value.items():
                    check_value(v, f"{path}.{k}")
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    check_value(item, f"{path}[{i}]")
        
        # Check all canonical sections
        for section, content in canonical.items():
            check_value(content, section)
        
        return warnings
    
    def persist_generation_run(self, cve_id: str, prompt: str, raw_response: str, 
                             validation_result: Dict[str, Any], retrieval_run_id: Optional[int] = None) -> Optional[int]:
        """
        Persist generation run to database.
        
        Args:
            cve_id: CVE identifier
            prompt: Generated prompt
            raw_response: Raw LLM response
            validation_result: Validation result dictionary
            retrieval_run_id: Optional retrieval run ID
            
        Returns:
            Generation run ID or None
        """
        try:
            # Determine status based on validation
            if validation_result.get("validation_passed", False):
                status = "completed"
                generation_source = "canonical_pipeline_success"
                llm_error_info = None
            else:
                status = "failed"
                generation_source = "canonical_pipeline_failed"
                llm_error_info = json.dumps({
                    "validation_errors": validation_result.get("errors", []),
                    "validation_warnings": validation_result.get("warnings", []),
                    "schema_compliance": validation_result.get("schema_compliance", {})
                })
            
            # Build insert data
            insert_data = {
                "cve_id": cve_id,
                "prompt": prompt,
                "prompt_text": prompt,
                "response": raw_response,
                "raw_response": raw_response,
                "status": status,
                "generation_source": generation_source,
                "llm_error_info": llm_error_info,
                "created_at": "NOW()"
            }
            
            # Add retrieval run ID if available
            if retrieval_run_id is not None:
                insert_data["retrieval_run_id"] = retrieval_run_id
            
            # Add validation debug info
            debug_info = validation_result.get("debug_info", {})
            if debug_info:
                insert_data["metadata"] = json.dumps({
                    "validation_debug": debug_info,
                    "pipeline_version": "v0.2.1_canonical"
                })
            
            # Insert generation run
            generation_run_id = self.db.insert_dynamic(
                "public.generation_runs",
                insert_data,
                returning="id"
            )
            
            logger.info(f"Persisted generation run ID: {generation_run_id}, status: {status}")
            return generation_run_id
            
        except Exception as e:
            logger.error(f"Failed to persist generation run: {e}")
            return None