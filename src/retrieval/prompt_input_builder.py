#!/usr/bin/env python3
"""
Prompt Input Builder for Playbook Engine
Version: v0.2.1-fix
Timestamp: 2026-04-08

Purpose:
- Collect all generation inputs before prompt rendering
- Build complete input package for prompt construction
- Ensure generation script uses this as the only input package
"""

import json
import logging
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PromptInputBuilder:
    """
    Builds complete prompt input package from collected evidence.
    
    Purpose:
    - Collect all generation inputs before prompt rendering
    - Return single dict with all required inputs
    - Ensure generation script uses this as the only input package
    """
    
    def __init__(self, cve_id: str, context_snapshot: Dict[str, Any], 
                 evidence_collector: Any, template_data: Dict[str, Any]):
        """
        Initialize prompt input builder.
        
        Args:
            cve_id: Target CVE identifier
            context_snapshot: Context data from playbook_engine
            evidence_collector: EvidenceCollector instance with collected evidence
            template_data: Prompt template data from database
        """
        self.cve_id = cve_id
        self.context_snapshot = context_snapshot
        self.evidence_collector = evidence_collector
        self.template_data = template_data
        
        logger.info(f"PromptInputBuilder initialized for {cve_id}")
    
    def build_input_package(self) -> Dict[str, Any]:
        """
        Build complete prompt input package.
        
        Returns:
            Complete input package dict
        """
        logger.info("Building complete prompt input package...")
        
        # Get evidence data from collector
        retrieval_decision = self.evidence_collector.get_retrieval_decision()
        retrieved_evidence = self.evidence_collector.get_all_evidence()
        source_indexes = self.evidence_collector.get_source_indexes()
        
        # Normalize context snapshot
        normalized_context = self._normalize_context_snapshot()
        
        # Extract template blocks
        template_blocks = self._extract_template_blocks()
        
        # Build the complete package
        input_package = {
            "cve_id": self.cve_id,
            "context_snapshot": normalized_context,
            "retrieval_decision": retrieval_decision,
            "retrieved_evidence": retrieved_evidence,
            "source_indexes": source_indexes,
            "template": template_blocks,
            "evidence_count": len(retrieved_evidence),
            "evidence_sources": source_indexes,
            "retrieval_quality": self._assess_retrieval_quality(retrieval_decision, retrieved_evidence)
        }
        
        logger.info(f"Built input package with {len(retrieved_evidence)} evidence items")
        return input_package
    
    def _normalize_context_snapshot(self) -> Dict[str, Any]:
        """Normalize context snapshot for prompt inclusion with richer NVD/CVE factors."""
        normalized = {
            # Basic CVE info
            "cve_id": self.context_snapshot.get("cve_id", self.cve_id),
            "description": self.context_snapshot.get("description", ""),
            "cvss_score": self.context_snapshot.get("cvss_score", 0),
            "severity": self.context_snapshot.get("severity", ""),
            "cwe": self.context_snapshot.get("cwe", ""),
            "vulnerability_type": self.context_snapshot.get("vulnerability_type", ""),
            
            # Affected components (extract from various possible fields)
            "affected_os": self._extract_affected_os(),
            "affected_software": self._extract_affected_software(),
            "package_name": self.context_snapshot.get("package_name", ""),
            "affected_versions": self.context_snapshot.get("affected_versions", ""),
            "fixed_versions": self.context_snapshot.get("fixed_versions", ""),
            "language_runtime": self.context_snapshot.get("language_runtime", ""),
            "framework_or_platform": self.context_snapshot.get("framework_or_platform", ""),
            
            # CVSS metrics
            "attack_vector": self.context_snapshot.get("attack_vector", ""),
            "attack_complexity": self.context_snapshot.get("attack_complexity", ""),
            "privileges_required": self.context_snapshot.get("privileges_required", ""),
            "user_interaction": self.context_snapshot.get("user_interaction", ""),
            "scope": self.context_snapshot.get("scope", ""),
            "confidentiality_impact": self.context_snapshot.get("confidentiality_impact", ""),
            "integrity_impact": self.context_snapshot.get("integrity_impact", ""),
            "availability_impact": self.context_snapshot.get("availability_impact", ""),
            
            # Deployment and remediation context
            "network_exposure": self.context_snapshot.get("network_exposure", ""),
            "deployment_type": self.context_snapshot.get("deployment_type", ""),
            "remediation_constraints": self.context_snapshot.get("remediation_constraints", ""),
            "vendor": self.context_snapshot.get("vendor", ""),
            "product": self.context_snapshot.get("product", ""),
            "component": self.context_snapshot.get("component", ""),
            "patch_available": self.context_snapshot.get("patch_available", False),
            "workarounds_available": self.context_snapshot.get("workarounds_available", False),
            
            # Temporal info
            "published_date": self.context_snapshot.get("published_date", ""),
            "last_modified_date": self.context_snapshot.get("last_modified_date", ""),
            
            # References
            "references": self.context_snapshot.get("references", []),
            
            # Legacy fields for backward compatibility
            "affected_products": self.context_snapshot.get("affected_products", [])
        }
        
        # Clean up empty values
        cleaned = {k: v for k, v in normalized.items() if v not in [None, "", [], {}, False]}
        
        return cleaned
    
    def _extract_affected_os(self) -> str:
        """Extract affected OS from context snapshot."""
        # Try to extract OS from various possible fields
        os_fields = [
            self.context_snapshot.get("affected_os", ""),
            self.context_snapshot.get("operating_system", ""),
            self.context_snapshot.get("platform", ""),
        ]
        
        # Also check description for OS mentions
        description = self.context_snapshot.get("description", "").lower()
        os_keywords = {
            "Linux": ["linux", "ubuntu", "debian", "centos", "redhat", "fedora", "rhel"],
            "Windows": ["windows", "microsoft"],
            "macOS": ["macos", "mac os", "apple"],
            "Android": ["android"],
            "iOS": ["ios", "iphone"]
        }
        
        for os_name, keywords in os_keywords.items():
            if any(keyword in description for keyword in keywords):
                return os_name
        
        # Return first non-empty OS field
        for field in os_fields:
            if field:
                return field
        
        return ""
    
    def _extract_affected_software(self) -> str:
        """Extract affected software from context snapshot."""
        # Try to extract software from various possible fields
        software_fields = [
            self.context_snapshot.get("affected_software", ""),
            self.context_snapshot.get("software", ""),
            self.context_snapshot.get("product", ""),
            self.context_snapshot.get("component", ""),
            self.context_snapshot.get("package_name", ""),
        ]
        
        # Also check description for software mentions
        description = self.context_snapshot.get("description", "").lower()
        
        # Common software patterns in descriptions
        software_patterns = [
            ("Apache", ["apache"]),
            ("Nginx", ["nginx"]),
            ("MySQL", ["mysql"]),
            ("PostgreSQL", ["postgresql", "postgres"]),
            ("Redis", ["redis"]),
            ("Docker", ["docker"]),
            ("Kubernetes", ["kubernetes", "k8s"]),
            ("WordPress", ["wordpress"]),
            ("Drupal", ["drupal"]),
            ("Joomla", ["joomla"]),
        ]
        
        for software_name, patterns in software_patterns:
            if any(pattern in description for pattern in patterns):
                return software_name
        
        # Return first non-empty software field
        for field in software_fields:
            if field:
                return field
        
        return ""
    
    def _extract_template_blocks(self) -> Dict[str, Any]:
        """Extract template blocks from template data."""
        blocks = {
            "system_block": self.template_data.get('system_block', ''),
            "instruction_block": self.template_data.get('instruction_block', ''),
            "workflow_block": self.template_data.get('workflow_block', ''),
            "output_schema_block": self.template_data.get('output_schema_block', ''),
            "template_name": self.template_data.get('template_name', ''),
            "template_version": self.template_data.get('version', ''),
            "template_id": self.template_data.get('id'),
            "template_version_id": self.template_data.get('template_version_id')
        }
        
        # Clean up empty values
        cleaned = {k: v for k, v in blocks.items() if v not in [None, "", [], {}]}
        
        return cleaned
    
    def _assess_retrieval_quality(self, retrieval_decision: str, 
                                 retrieved_evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess the quality of retrieved evidence."""
        quality = {
            "decision": retrieval_decision,
            "evidence_count": len(retrieved_evidence),
            "has_opensearch_evidence": False,
            "has_vulnstrike_evidence": False,
            "average_score": 0.0,
            "source_diversity": 0
        }
        
        if not retrieved_evidence:
            return quality
        
        # Calculate average score
        total_score = 0.0
        valid_scores = 0
        source_set = set()
        
        for evidence in retrieved_evidence:
            score = evidence.get('score', 0)
            if score > 0:
                total_score += score
                valid_scores += 1
            
            source_index = evidence.get('source_index', '')
            if source_index:
                source_set.add(source_index)
            
            # Check evidence sources
            if 'opensearch' in source_index.lower():
                quality["has_opensearch_evidence"] = True
            elif 'vulnstrike' in source_index.lower():
                quality["has_vulnstrike_evidence"] = True
        
        if valid_scores > 0:
            quality["average_score"] = total_score / valid_scores
        
        quality["source_diversity"] = len(source_set)
        
        return quality
    
    def render_prompt(self, input_package: Dict[str, Any]) -> str:
        """
        Render prompt from complete input package.
        
        Args:
            input_package: Complete input package from build_input_package()
            
        Returns:
            Rendered prompt string
        """
        logger.info("Rendering prompt from complete input package...")
        
        prompt_parts = []
        
        # Add system block if present
        system_block = input_package['template'].get('system_block')
        if system_block:
            prompt_parts.append(f"## System Role\n\n{system_block}")
        
        # Add instruction block if present
        instruction_block = input_package['template'].get('instruction_block')
        if instruction_block:
            prompt_parts.append(f"## Instructions\n\n{instruction_block}")
        
        # Add workflow block if present
        workflow_block = input_package['template'].get('workflow_block')
        if workflow_block:
            prompt_parts.append(f"## Workflow\n\n{workflow_block}")
        
        # Add CVE context section
        context_section = self._render_context_section(input_package['context_snapshot'])
        prompt_parts.append(context_section)
        
        # Add retrieval decision and evidence section
        evidence_section = self._render_evidence_section(
            input_package['retrieval_decision'],
            input_package['retrieved_evidence'],
            input_package['source_indexes']
        )
        prompt_parts.append(evidence_section)
        
        # Add output schema if present
        output_schema = input_package['template'].get('output_schema_block')
        if output_schema:
            prompt_parts.append(f"## Output Schema\n\n{output_schema}")
        
        # Join all parts
        rendered_prompt = "\n\n".join(prompt_parts)
        
        logger.info(f"Rendered prompt ({len(rendered_prompt)} chars)")
        return rendered_prompt
    
    def validate_prompt(self, prompt: str, input_package: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate that prompt contains all required sections.
        
        Args:
            prompt: Rendered prompt string
            input_package: Input package used to render prompt
            
        Returns:
            Validation results dict
        """
        validation = {
            "is_valid": True,
            "errors": [],
            "warnings": [],
            "sections_found": {},
            "requirements_met": {}
        }
        
        # Check for required sections
        required_sections = [
            ("CVE Context", "CVE context section"),
            ("Retrieved Evidence", "Retrieved evidence section"),
            ("Output Schema", "Output schema section")
        ]
        
        for section_key, section_name in required_sections:
            if section_key in prompt:
                validation["sections_found"][section_key] = True
                validation["requirements_met"][section_name] = True
            else:
                validation["sections_found"][section_key] = False
                validation["requirements_met"][section_name] = False
                validation["errors"].append(f"Missing {section_name}")
                validation["is_valid"] = False
        
        # Check for CVE ID in prompt
        cve_id = input_package.get('cve_id', '')
        if cve_id and cve_id in prompt:
            validation["requirements_met"]["CVE ID included"] = True
        else:
            validation["warnings"].append(f"CVE ID '{cve_id}' not found in prompt")
            validation["requirements_met"]["CVE ID included"] = False
        
        # Check for evidence in prompt
        evidence_count = len(input_package.get('retrieved_evidence', []))
        if evidence_count > 0:
            # Check if evidence is referenced in prompt
            evidence_keywords = ["evidence", "retrieved", "document", "source"]
            has_evidence_ref = any(keyword in prompt.lower() for keyword in evidence_keywords)
            if has_evidence_ref:
                validation["requirements_met"]["Evidence referenced"] = True
            else:
                validation["warnings"].append("Evidence not referenced in prompt")
                validation["requirements_met"]["Evidence referenced"] = False
        else:
            validation["requirements_met"]["Evidence referenced"] = True  # No evidence to reference
        
        # Check prompt length
        prompt_length = len(prompt)
        if prompt_length < 100:
            validation["errors"].append(f"Prompt too short ({prompt_length} chars)")
            validation["is_valid"] = False
        elif prompt_length > 10000:
            validation["warnings"].append(f"Prompt very long ({prompt_length} chars)")
        
        validation["prompt_length"] = prompt_length
        validation["evidence_count"] = evidence_count
        
        return validation
    
    def _render_context_section(self, context_snapshot: Dict[str, Any]) -> str:
        """Render CVE context section with richer NVD/CVE factors."""
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
    
    def _render_evidence_section(self, retrieval_decision: str, 
                                retrieved_evidence: List[Dict[str, Any]],
                                source_indexes: List[str]) -> str:
        """Render retrieved evidence section."""
        section = "## Retrieved Evidence\n\n"
        
        # Add retrieval decision note
        decision_notes = {
            "sufficient": "Sufficient evidence retrieved from knowledge base.",
            "weak": "Limited evidence retrieved - generation may be degraded.",
            "empty": "No evidence retrieved - consider manual review."
        }
        
        section += f"**Retrieval Status:** {retrieval_decision.upper()}\n"
        section += f"**Note:** {decision_notes.get(retrieval_decision, 'Unknown retrieval status.')}\n\n"
        
        # Add source summary
        if source_indexes:
            section += f"**Sources:** {', '.join(source_indexes)}\n\n"
        
        # Add evidence documents
        if retrieved_evidence:
            section += "### Evidence Documents:\n\n"
            
            for i, evidence in enumerate(retrieved_evidence[:10], 1):  # Limit to 10 documents
                title = evidence.get('title', 'Untitled Document')
                source = evidence.get('source_index', 'Unknown Source')
                score = evidence.get('score', 0)
                content = evidence.get('content', '')
                
                section += f"#### Document {i}: {title}\n"
                section += f"**Source:** {source}\n"
                section += f"**Relevance Score:** {score:.3f}\n"
                section += f"**Content:** {content[:500]}"
                if len(content) > 500:
                    section += "..."
                section += "\n\n"
            
            if len(retrieved_evidence) > 10:
                section += f"*... and {len(retrieved_evidence) - 10} more documents*\n\n"
        else:
            section += "**No evidence documents retrieved.**\n\n"
        
        return section


# Convenience function for quick access
def build_prompt_inputs(cve_id: str, context_snapshot: Dict[str, Any], 
                       evidence_collector: Any, template_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Factory function to build complete prompt input package.
    
    Args:
        cve_id: Target CVE identifier
        context_snapshot: Context data from playbook_engine
        evidence_collector: EvidenceCollector instance
        template_data: Prompt template data
        
    Returns:
        Complete input package dict
    """
    builder = PromptInputBuilder(cve_id, context_snapshot, evidence_collector, template_data)
    return builder.build_input_package()