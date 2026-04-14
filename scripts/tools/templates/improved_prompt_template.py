#!/usr/bin/env python3
"""
Improved Prompt Template for Playbook Engine - Group 6
Version: v1.1.0
Timestamp: 2026-04-08

This module contains the improved prompt template based on the user's 2 better examples.
"""

# Improved system block based on examples
IMPROVED_SYSTEM_BLOCK = """You are a security analyst specializing in vulnerability remediation.
Your task is to generate detailed, actionable remediation playbooks for security teams based on CVE information and retrieved evidence.

CRITICAL INSTRUCTIONS:
1. Output MUST be valid JSON only - no explanatory text outside JSON
2. Do NOT include markdown fences (```json or ```)
3. Follow the exact output schema provided
4. All fields in the schema are REQUIRED
5. remediation_steps must be non-empty
6. Each remediation step must include all required fields
7. verification_procedures and rollback_procedures must be provided
8. Base your recommendations on the specific vulnerability context and evidence provided"""

# Improved instruction block based on examples
IMPROVED_INSTRUCTION_BLOCK = """Analyze the provided CVE context and retrieved evidence to generate a comprehensive security playbook.

REQUIREMENTS:
1. Output MUST be pure JSON following the exact schema below
2. Do NOT include any text before or after the JSON
3. The JSON must parse successfully
4. All fields in the schema are REQUIRED and must be populated
5. remediation_steps must contain at least one step
6. Each remediation step must include:
   - step_number (integer)
   - description (string)
   - commands (array of strings)
   - verification (string)
   - evidence_based (boolean)
7. Include verification_procedures and rollback_procedures
8. All arrays must be non-empty where applicable

SPECIFIC GUIDANCE:
- Consider the affected OS, software, package, and versions when generating remediation steps
- Account for vulnerability type, attack complexity, privileges required, and user interaction
- Factor in deployment context and remediation constraints
- Use the retrieved evidence to inform evidence_based field in remediation steps
- Provide OS-specific commands and procedures based on the affected systems
- Include pre-remediation checks and backups where appropriate
- Consider both repository-based updates and manual installation approaches"""

# Improved workflow block based on examples
IMPROVED_WORKFLOW_BLOCK = """1. Analyze CVE context including affected OS/software/package/versions
2. Review retrieved evidence from vulnerability databases
3. Identify specific remediation approach based on:
   - Available package updates in repositories
   - Need for manual installation or source compilation
   - OS/distribution-specific procedures
4. Generate step-by-step remediation procedures considering:
   - Pre-remediation checks and backups
   - Package manager commands (apt, yum, dnf, etc.) or manual installation steps
   - Configuration changes and file edits
   - Service restarts and dependency management
5. Include verification procedures for each step
6. Include rollback procedures for safety
7. Format output as pure JSON following exact schema
8. Validate JSON structure matches schema
9. Output ONLY the JSON - no other text"""

# Improved output schema block
IMPROVED_OUTPUT_SCHEMA_BLOCK = """{
  "playbook": {
    "title": "string - descriptive title of the playbook including CVE ID and affected component",
    "cve_id": "string - CVE identifier (e.g., CVE-2025-12345)",
    "severity": "string - CVSS severity (Critical/High/Medium/Low)",
    "retrieval_metadata": {
      "decision": "string - retrieval decision (weak/sufficient)",
      "evidence_count": "integer - number of evidence documents used",
      "source_indexes": ["string"] - array of source indexes used
    },
    "affected_components": ["string"] - list of affected software/components with versions if available,
    "vulnerability_context": {
      "affected_os": "string - affected operating system/distribution",
      "affected_software": "string - affected software/package name",
      "affected_versions": "string - affected version range",
      "fixed_versions": "string - fixed version if available",
      "vulnerability_type": "string - type of vulnerability",
      "attack_complexity": "string - attack complexity level",
      "privileges_required": "string - privileges required for exploitation",
      "user_interaction": "string - user interaction required",
      "scope": "string - scope of the vulnerability",
      "deployment_type": "string - deployment context (server, desktop, cloud, etc.)",
      "remediation_constraints": "string - any constraints on remediation"
    },
    "remediation_steps": [
      {
        "step_number": 1,
        "description": "string - detailed description of the remediation step including OS/software context",
        "commands": ["string"] - array of executable commands or actions specific to the OS/package,
        "verification": "string - how to verify this step was successful",
        "evidence_based": true
      }
    ],
    "verification_procedures": ["string"] - array of overall verification procedures,
    "rollback_procedures": ["string"] - array of rollback procedures for safety,
    "references": ["string"] - array of reference URLs or documents
  }
}"""

# Richer context fields to extract from NVD/CVE data
RICHER_CONTEXT_FIELDS = [
    # Basic CVE info
    "cve_id",
    "description",
    "cvss_score",
    "severity",
    "cwe",
    "vulnerability_type",
    
    # Affected components
    "affected_os",
    "affected_software",
    "package_name",
    "affected_versions",
    "fixed_versions",
    "language_runtime",
    "framework_or_platform",
    
    # CVSS metrics
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    
    # Deployment and remediation context
    "network_exposure",
    "deployment_type",
    "remediation_constraints",
    "vendor",
    "product",
    "component",
    "patch_available",
    "workarounds_available",
    
    # Temporal info
    "published_date",
    "last_modified_date",
    
    # References
    "references"
]

def get_improved_template_blocks():
    """Return the improved template blocks for insertion into database."""
    return {
        "system_block": IMPROVED_SYSTEM_BLOCK,
        "instruction_block": IMPROVED_INSTRUCTION_BLOCK,
        "workflow_block": IMPROVED_WORKFLOW_BLOCK,
        "output_schema_block": IMPROVED_OUTPUT_SCHEMA_BLOCK
    }

def create_improved_normalization_function():
    """Create the improved normalization function for prompt_input_builder.py."""
    
    normalization_code = '''
    def _normalize_context_snapshot(self) -> Dict[str, Any]:
        """Normalize context snapshot for prompt inclusion with richer NVD/CVE factors."""
        # Extract basic fields
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
            "linux": ["linux", "ubuntu", "debian", "centos", "redhat", "fedora"],
            "windows": ["windows", "microsoft"],
            "macos": ["macos", "mac os", "apple"],
            "android": ["android"],
            "ios": ["ios", "iphone"]
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
        ]
        
        # Also check description for software mentions
        description = self.context_snapshot.get("description", "").lower()
        
        # Return first non-empty software field
        for field in software_fields:
            if field:
                return field
        
        return ""
    '''
    
    return normalization_code

if __name__ == "__main__":
    print("Improved Prompt Template v1.1.0")
    print("=" * 50)
    print(f"System block length: {len(IMPROVED_SYSTEM_BLOCK)}")
    print(f"Instruction block length: {len(IMPROVED_INSTRUCTION_BLOCK)}")
    print(f"Workflow block length: {len(IMPROVED_WORKFLOW_BLOCK)}")
    print(f"Output schema block length: {len(IMPROVED_OUTPUT_SCHEMA_BLOCK)}")
    print(f"\nRicher context fields defined: {len(RICHER_CONTEXT_FIELDS)}")