"""
Canonical Prompt Builder for Continuous Pipeline v0.2.0
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z

Purpose:
- Port the proven prompt builder logic from Phase 1 runner
- Use same evidence collection and template system
- Ensure prompt/schema convergence
"""

import json
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class CanonicalPromptBuilder:
    """
    Canonical prompt builder using the same logic as Phase 1 runner.
    
    This replicates the behavior of src.retrieval.prompt_input_builder.PromptInputBuilder
    but adapted for the continuous pipeline context.
    """
    
    def __init__(self, db_client):
        self.db = db_client
        logger.info("CanonicalPromptBuilder initialized")
    
    def _load_active_prompt_template_version(self) -> Dict[str, Any]:
        """Load active prompt template version from database."""
        row = self.db.fetch_one(
            """
            SELECT
                ptv.*,
                pt.name AS template_name
            FROM prompt_template_versions ptv
            JOIN prompt_templates pt
              ON ptv.template_id = pt.id
            WHERE ptv.is_active = TRUE
            ORDER BY ptv.id DESC
            LIMIT 1
            """
        )
        if not row:
            raise RuntimeError("No active prompt template version found")
        logger.info(f"Found active template version ID: {row['id']}")
        return row
    
    def _normalize_context_snapshot(self, context_snapshot: Dict[str, Any], cve_id: str) -> Dict[str, Any]:
        """Normalize context snapshot for prompt inclusion."""
        # If context_snapshot is already a dict with proper structure, use it
        if isinstance(context_snapshot, dict) and 'cve_id' in context_snapshot:
            return context_snapshot
        
        # Otherwise, normalize from raw CVE document
        normalized = {
            "cve_id": cve_id,
            "description": context_snapshot.get("description", ""),
            "cvss_score": context_snapshot.get("cvss_score", 0),
            "severity": context_snapshot.get("severity", ""),
            "cwe": context_snapshot.get("cwe", ""),
            "vulnerability_type": context_snapshot.get("vulnerability_type", ""),
            "affected_os": context_snapshot.get("affected_os", ""),
            "affected_software": context_snapshot.get("affected_software", ""),
            "package_name": context_snapshot.get("package_name", ""),
            "affected_versions": context_snapshot.get("affected_versions", ""),
            "fixed_versions": context_snapshot.get("fixed_versions", ""),
            "attack_vector": context_snapshot.get("attack_vector", ""),
            "attack_complexity": context_snapshot.get("attack_complexity", ""),
            "privileges_required": context_snapshot.get("privileges_required", ""),
            "user_interaction": context_snapshot.get("user_interaction", ""),
            "scope": context_snapshot.get("scope", ""),
            "confidentiality_impact": context_snapshot.get("confidentiality_impact", ""),
            "integrity_impact": context_snapshot.get("integrity_impact", ""),
            "availability_impact": context_snapshot.get("availability_impact", ""),
            "network_exposure": context_snapshot.get("network_exposure", ""),
            "deployment_type": context_snapshot.get("deployment_type", ""),
            "remediation_constraints": context_snapshot.get("remediation_constraints", ""),
            "vendor": context_snapshot.get("vendor", ""),
            "product": context_snapshot.get("product", ""),
            "component": context_snapshot.get("component", ""),
            "patch_available": context_snapshot.get("patch_available", False),
            "workarounds_available": context_snapshot.get("workarounds_available", False),
            "published_date": context_snapshot.get("published_date", ""),
            "last_modified_date": context_snapshot.get("last_modified_date", ""),
            "references": context_snapshot.get("references", []),
            "affected_products": context_snapshot.get("affected_products", [])
        }
        
        # Clean up empty values
        cleaned = {k: v for k, v in normalized.items() if v not in [None, "", [], {}, False]}
        return cleaned
    
    def _extract_template_blocks(self, template_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract template blocks from template data."""
        blocks = {
            "system_block": template_data.get('system_block', ''),
            "instruction_block": template_data.get('instruction_block', ''),
            "workflow_block": template_data.get('workflow_block', ''),
            "output_schema_block": template_data.get('output_schema_block', ''),
            "template_name": template_data.get('template_name', ''),
            "template_version": template_data.get('version', ''),
            "template_id": template_data.get('id'),
            "template_version_id": template_data.get('template_version_id')
        }
        
        # Clean up empty values
        cleaned = {k: v for k, v in blocks.items() if v not in [None, "", [], {}]}
        return cleaned
    
    def _render_context_section(self, context_snapshot: Dict[str, Any]) -> str:
        """Render CVE context section."""
        section = "## CVE Context Data\n\n"
        
        # Add basic CVE info
        section += f"**CVE ID:** {context_snapshot.get('cve_id', 'Unknown')}\n"
        section += f"**Description:** {context_snapshot.get('description', 'No description available')}\n"
        
        # Add CVSS score and severity if available
        cvss_score = context_snapshot.get('cvss_score')
        if cvss_score:
            section += f"**CVSS Score:** {cvss_score}\n"
        
        severity = context_snapshot.get('severity')
        if severity:
            section += f"**Severity:** {severity}\n"
        
        # Add CWE if available
        cwe = context_snapshot.get('cwe')
        if cwe:
            section += f"**CWE:** {cwe}\n"
        
        # Add vulnerability type if available
        vuln_type = context_snapshot.get('vulnerability_type')
        if vuln_type:
            section += f"**Vulnerability Type:** {vuln_type}\n"
        
        # Add affected OS/software/versions if available
        affected_os = context_snapshot.get('affected_os')
        if affected_os:
            section += f"**Affected OS:** {affected_os}\n"
        
        affected_software = context_snapshot.get('affected_software')
        if affected_software:
            section += f"**Affected Software:** {affected_software}\n"
        
        package_name = context_snapshot.get('package_name')
        if package_name:
            section += f"**Package Name:** {package_name}\n"
        
        affected_versions = context_snapshot.get('affected_versions')
        if affected_versions:
            section += f"**Affected Versions:** {affected_versions}\n"
        
        fixed_versions = context_snapshot.get('fixed_versions')
        if fixed_versions:
            section += f"**Fixed Versions:** {fixed_versions}\n"
        
        # Add CVSS metrics if available
        attack_vector = context_snapshot.get('attack_vector')
        if attack_vector:
            section += f"**Attack Vector:** {attack_vector}\n"
        
        attack_complexity = context_snapshot.get('attack_complexity')
        if attack_complexity:
            section += f"**Attack Complexity:** {attack_complexity}\n"
        
        privileges_required = context_snapshot.get('privileges_required')
        if privileges_required:
            section += f"**Privileges Required:** {privileges_required}\n"
        
        user_interaction = context_snapshot.get('user_interaction')
        if user_interaction:
            section += f"**User Interaction:** {user_interaction}\n"
        
        scope = context_snapshot.get('scope')
        if scope:
            section += f"**Scope:** {scope}\n"
        
        # Add deployment context if available
        deployment_type = context_snapshot.get('deployment_type')
        if deployment_type:
            section += f"**Deployment Type:** {deployment_type}\n"
        
        remediation_constraints = context_snapshot.get('remediation_constraints')
        if remediation_constraints:
            section += f"**Remediation Constraints:** {remediation_constraints}\n"
        
        patch_available = context_snapshot.get('patch_available')
        if patch_available:
            section += f"**Patch Available:** {patch_available}\n"
        
        workarounds_available = context_snapshot.get('workarounds_available')
        if workarounds_available:
            section += f"**Workarounds Available:** {workarounds_available}\n"
        
        # Add legacy affected products if available
        affected_products = context_snapshot.get('affected_products', [])
        if affected_products:
            section += f"**Affected Products:** {', '.join(affected_products)}\n"
        
        # Add references if available
        references = context_snapshot.get('references', [])
        if references:
            section += f"**References:**\n"
            for ref in references[:5]:  # Limit to 5 references
                section += f"- {ref}\n"
        
        return section
    
    def _render_evidence_section(self, evidence_items: List[Dict[str, Any]]) -> str:
        """Render retrieved evidence section."""
        section = "## Retrieved Evidence\n\n"
        
        # Add retrieval decision note (simplified for continuous pipeline)
        section += f"**Retrieval Status:** SUFFICIENT\n"
        section += f"**Note:** Evidence retrieved from OpenSearch NVD index.\n\n"
        
        # Add evidence documents
        if evidence_items:
            section += "### Evidence Documents:\n\n"
            
            for i, evidence in enumerate(evidence_items[:5], 1):  # Limit to 5 documents
                title = evidence.get('title', 'CVE Document')
                source = evidence.get('source_index', 'opensearch_nvd')
                content = evidence.get('content', '')
                
                section += f"#### Document {i}: {title}\n"
                section += f"**Source:** {source}\n"
                section += f"**Content:** {content[:300]}"
                if len(content) > 300:
                    section += "..."
                section += "\n\n"
            
            if len(evidence_items) > 5:
                section += f"*... and {len(evidence_items) - 5} more documents*\n\n"
        else:
            section += "**No evidence documents retrieved.**\n\n"
        
        return section
    
    def build_prompt(self, cve_id: str, cve_doc: Dict[str, Any], evidence_items: List[Dict[str, Any]] = None) -> str:
        """
        Build canonical prompt using the same logic as Phase 1 runner.
        
        Args:
            cve_id: CVE identifier
            cve_doc: CVE document from OpenSearch
            evidence_items: List of evidence documents (optional)
            
        Returns:
            Rendered prompt string
        """
        logger.info(f"Building canonical prompt for {cve_id}")
        
        # Load active template
        try:
            template_data = self._load_active_prompt_template_version()
            template_blocks = self._extract_template_blocks(template_data)
        except Exception as e:
            logger.warning(f"Failed to load active template: {e}. Using fallback template.")
            template_blocks = {
                "system_block": "You are a cybersecurity expert generating remediation playbooks for vulnerabilities.",
                "instruction_block": "Generate a comprehensive remediation playbook for the given CVE.",
                "workflow_block": "1. Analyze the CVE context and evidence\n2. Generate structured playbook\n3. Include all required sections",
                "output_schema_block": "Return valid JSON with top-level key 'playbook' containing: cve_id, summary, impact, detection, remediation_steps, validation_steps, rollback_steps, references."
            }
        
        # Normalize context
        normalized_context = self._normalize_context_snapshot(cve_doc, cve_id)
        
        # Prepare evidence items
        if evidence_items is None:
            evidence_items = [{
                "title": f"CVE-{cve_id} Document",
                "source_index": "opensearch_nvd",
                "content": json.dumps(cve_doc, indent=2)[:1000]
            }]
        
        # Build prompt parts
        prompt_parts = []
        
        # Add system block if present
        system_block = template_blocks.get('system_block')
        if system_block:
            prompt_parts.append(f"## System Role\n\n{system_block}")
        
        # Add instruction block if present
        instruction_block = template_blocks.get('instruction_block')
        if instruction_block:
            prompt_parts.append(f"## Instructions\n\n{instruction_block}")
        
        # Add workflow block if present
        workflow_block = template_blocks.get('workflow_block')
        if workflow_block:
            prompt_parts.append(f"## Workflow\n\n{workflow_block}")
        
        # Add CVE context section
        context_section = self._render_context_section(normalized_context)
        prompt_parts.append(context_section)
        
        # Add evidence section
        evidence_section = self._render_evidence_section(evidence_items)
        prompt_parts.append(evidence_section)
        
        # Add output schema if present
        output_schema = template_blocks.get('output_schema_block')
        if output_schema:
            prompt_parts.append(f"## Output Schema\n\n{output_schema}")
        else:
            # Fallback output schema
            prompt_parts.append("## Output Schema\n\nReturn valid JSON with a top-level key named 'playbook'. The playbook object must include: cve_id, summary, impact, detection, remediation_steps, validation_steps, rollback_steps, references.")
        
        # Join all parts
        rendered_prompt = "\n\n".join(prompt_parts)
        
        logger.info(f"Canonical prompt built: {len(rendered_prompt)} chars")
        logger.debug(f"Prompt sections: {len(prompt_parts)}")
        
        return rendered_prompt