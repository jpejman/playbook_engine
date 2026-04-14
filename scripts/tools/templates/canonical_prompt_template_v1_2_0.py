#!/usr/bin/env python3
"""
Canonical Prompt Template for Playbook Engine - Group 6.6
Version: v1.2.0
Timestamp: 2026-04-08

This module contains the canonical prompt template aligned with the canonical playbook schema v0.1.0.
"""

# Canonical system block with schema enforcement
CANONICAL_SYSTEM_BLOCK = """You are a security analyst specializing in vulnerability remediation.
Your task is to generate detailed, actionable remediation playbooks for security teams based on CVE information and retrieved evidence.

CRITICAL INSTRUCTIONS:
1. Output MUST be valid JSON only - no explanatory text outside JSON
2. Do NOT include markdown fences (```json or ```)
3. Follow the EXACT canonical playbook schema provided below
4. All REQUIRED fields in the schema must be populated
5. Workflows array must contain at least one workflow
6. Each workflow must contain at least one step
7. All steps must include ALL required step fields
8. Base your recommendations on the specific vulnerability context and evidence provided
9. Output ONLY the JSON - no other text"""

# Canonical instruction block with anti-generic enforcement
CANONICAL_INSTRUCTION_BLOCK = """Analyze the provided CVE context and retrieved evidence to generate a comprehensive security playbook following the canonical playbook schema.

REQUIREMENTS:
1. Output MUST be pure JSON following the EXACT canonical schema below
2. Do NOT include any text before or after the JSON
3. The JSON must parse successfully
4. All REQUIRED fields in the schema must be populated
5. Workflows array must contain at least one workflow
6. Each workflow must contain at least one step
7. All arrays must be non-empty where applicable

ANTI-GENERIC ENFORCEMENT RULES:
1. FORBID generic remediation like "update to latest version" - use specific version numbers from context when available
2. REQUIRE OS/platform targeting - each step must specify target_os_or_platform
3. REQUIRE version specificity - use affected_versions and fixed_versions from context
4. REQUIRE workflow grouping - group steps into logical workflows (repository_update, manual_install, etc.)
5. REQUIRE evidence mapping - mark steps as evidence_based: true when based on retrieved evidence
6. REQUIRE rollback guidance - include rollback_hint for destructive operations
7. FORBID vague commands - provide specific executable commands
8. REQUIRE verification procedures - each step must include verification method

WORKFLOW TYPE GUIDANCE:
- repository_update: When package updates are available in repositories (use apt, yum, etc.)
- manual_install: When manual download/compilation is required
- configuration_hardening: When security configuration changes are needed
- network_isolation: When firewall/network rules are required
- other: For custom remediation paths

CONTEXT UTILIZATION:
- Use ALL available context fields (vendor, product, affected_versions, fixed_versions, etc.)
- Map retrieved evidence to evidence_based steps
- Consider OS/distribution specifics from context
- Account for deployment type and constraints"""

# Canonical workflow block
CANONICAL_WORKFLOW_BLOCK = """1. Analyze CVE context including ALL available fields (vendor, product, affected_versions, OS, etc.)
2. Review retrieved evidence from vulnerability databases
3. Identify specific remediation approach based on:
   - Available package updates in repositories
   - Need for manual installation or source compilation
   - OS/distribution-specific procedures
   - Configuration hardening requirements
   - Network isolation needs
4. Group remediation steps into logical workflows based on approach
5. Generate step-by-step remediation procedures considering:
   - Pre-remediation checks and backups
   - Package manager commands (apt, yum, dnf, etc.) or manual installation steps
   - Configuration changes and file edits
   - Service restarts and dependency management
   - Network/firewall rule updates
6. Include verification procedures for each step
7. Include rollback guidance for safety
8. Format output as pure JSON following EXACT canonical schema
9. Validate JSON structure matches schema
10. Output ONLY the JSON - no other text"""

# Canonical output schema block (aligned with canonical schema v0.1.0)
CANONICAL_OUTPUT_SCHEMA_BLOCK = """{
  "header": {
    "title": "string - Remediation Playbook for CVE-XXXX-XXXX (include CVE ID and affected component)",
    "cve_id": "string - CVE identifier (e.g., CVE-2025-12345) - MUST match input CVE",
    "vendor": "string - Vendor name from context (e.g., Microsoft, Apache, Linux Foundation)",
    "product": "string - Product name from context (e.g., Windows, httpd, Linux kernel)",
    "severity": "string - CVSS severity (Critical/High/Medium/Low) from context",
    "vulnerability_type": "string - Type of vulnerability (e.g., buffer overflow, XSS, privilege escalation)",
    "description": "string - Brief description of the vulnerability from context",
    "affected_versions": ["string"] - array of affected version ranges from context,
    "fixed_versions": ["string"] - array of fixed versions from context if available,
    "affected_platforms": ["string"] - array of affected platforms (Linux, Windows, macOS, Android, iOS) from context,
    "references": ["string"] - array of reference URLs from context and evidence
  },
  "pre_remediation_checks": {
    "required_checks": [
      {
        "check_id": "string - check_1, check_2, etc.",
        "description": "string - description of the check (e.g., verify system backup exists)",
        "commands": ["string"] - array of commands to perform the check,
        "expected_result": "string - expected outcome of the check"
      }
    ],
    "backup_steps": [
      {
        "step_id": "string - backup_1, backup_2, etc.",
        "description": "string - description of backup procedure",
        "commands": ["string"] - array of backup commands,
        "verification": "string - how to verify backup was successful"
      }
    ],
    "prerequisites": ["string"] - array of prerequisites (e.g., required tools, permissions, access)
  },
  "workflows": [
    {
      "workflow_id": "string - workflow_1, workflow_2, etc.",
      "workflow_name": "string - descriptive workflow name (e.g., Repository Update Workflow)",
      "workflow_type": "string - repository_update, manual_install, configuration_hardening, network_isolation, or other",
      "applicability_conditions": {
        "os_family": ["string"] - array of applicable OS families (Linux, Windows, macOS),
        "package_managers": ["string"] - array of applicable package managers (apt, yum, pip, npm, docker),
        "environments": ["string"] - array of applicable environments (production, staging, development, test)
      },
      "prerequisites": ["string"] - array of workflow-specific prerequisites,
      "steps": [
        {
          "step_number": 1,
          "title": "string - brief step title (e.g., Update package repositories)",
          "description": "string - detailed description including OS/software context",
          "commands": ["string"] - array of executable commands specific to OS/package,
          "target_os_or_platform": "string - target OS/platform for this step (e.g., Linux/Ubuntu, Windows Server 2022)",
          "expected_result": "string - what should happen when this step completes successfully",
          "verification": "string - how to verify this step was successful",
          "rollback_hint": "string - guidance for rolling back this step if needed",
          "evidence_based": true
        }
      ]
    }
  ],
  "post_remediation_validation": {
    "validation_steps": [
      {
        "step_id": "string - validation_1, validation_2, etc.",
        "description": "string - description of validation procedure",
        "commands": ["string"] - array of validation commands,
        "expected_outcomes": ["string"] - array of expected outcomes
      }
    ],
    "testing_procedures": [
      {
        "test_id": "string - test_1, test_2, etc.",
        "description": "string - description of test procedure",
        "commands": ["string"] - array of test commands,
        "pass_criteria": "string - criteria for passing the test"
      }
    ]
  },
  "additional_recommendations": [
    {
      "recommendation_id": "string - rec_1, rec_2, etc.",
      "category": "string - security_hardening, monitoring, backup, documentation, or other",
      "description": "string - recommendation description",
      "priority": "string - high, medium, or low",
      "implementation_guidance": "string - guidance on how to implement the recommendation"
    }
  ],
  "retrieval_metadata": {
    "decision": "string - retrieval decision (strong, weak, none) from evidence collector",
    "evidence_count": "integer - number of evidence documents used",
    "source_indexes": ["string"] - array of source indexes used,
    "generation_timestamp": "string - ISO 8601 timestamp of generation"
  }
}"""

# Enhanced context fields for canonical schema alignment
CANONICAL_CONTEXT_FIELDS = [
    # Header fields
    "cve_id",
    "vendor",
    "product",
    "severity",
    "vulnerability_type",
    "description",
    "affected_versions",
    "fixed_versions",
    "affected_platforms",
    
    # Vulnerability details
    "cwe",
    "cvss_score",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    
    # Deployment context
    "deployment_type",
    "network_exposure",
    "remediation_constraints",
    "component",
    "language_runtime",
    "framework_or_platform",
    
    # Package/software details
    "package_name",
    "software",
    "operating_system",
    "platform",
    
    # Temporal info
    "published_date",
    "last_modified_date",
    
    # References
    "references"
]

def get_canonical_template_blocks():
    """Return the canonical template blocks for insertion into database."""
    return {
        "system_block": CANONICAL_SYSTEM_BLOCK,
        "instruction_block": CANONICAL_INSTRUCTION_BLOCK,
        "workflow_block": CANONICAL_WORKFLOW_BLOCK,
        "output_schema_block": CANONICAL_OUTPUT_SCHEMA_BLOCK
    }

def create_canonical_normalization_function():
    """Create the canonical normalization function for prompt_input_builder.py."""
    
    normalization_code = '''
    def _normalize_context_snapshot_canonical(self) -> Dict[str, Any]:
        """Normalize context snapshot for canonical prompt inclusion."""
        # Extract all fields needed for canonical schema
        normalized = {
            # Header fields
            "cve_id": self.context_snapshot.get("cve_id", self.cve_id),
            "vendor": self.context_snapshot.get("vendor", ""),
            "product": self.context_snapshot.get("product", ""),
            "severity": self.context_snapshot.get("severity", ""),
            "vulnerability_type": self.context_snapshot.get("vulnerability_type", ""),
            "description": self.context_snapshot.get("description", ""),
            "affected_versions": self._extract_version_array("affected_versions"),
            "fixed_versions": self._extract_version_array("fixed_versions"),
            "affected_platforms": self._extract_affected_platforms(),
            
            # Vulnerability details
            "cwe": self.context_snapshot.get("cwe", ""),
            "cvss_score": self.context_snapshot.get("cvss_score", 0),
            "attack_vector": self.context_snapshot.get("attack_vector", ""),
            "attack_complexity": self.context_snapshot.get("attack_complexity", ""),
            "privileges_required": self.context_snapshot.get("privileges_required", ""),
            "user_interaction": self.context_snapshot.get("user_interaction", ""),
            "scope": self.context_snapshot.get("scope", ""),
            "confidentiality_impact": self.context_snapshot.get("confidentiality_impact", ""),
            "integrity_impact": self.context_snapshot.get("integrity_impact", ""),
            "availability_impact": self.context_snapshot.get("availability_impact", ""),
            
            # Deployment context
            "deployment_type": self.context_snapshot.get("deployment_type", ""),
            "network_exposure": self.context_snapshot.get("network_exposure", ""),
            "remediation_constraints": self.context_snapshot.get("remediation_constraints", ""),
            "component": self.context_snapshot.get("component", ""),
            "language_runtime": self.context_snapshot.get("language_runtime", ""),
            "framework_or_platform": self.context_snapshot.get("framework_or_platform", ""),
            
            # Package/software details
            "package_name": self.context_snapshot.get("package_name", ""),
            "software": self.context_snapshot.get("software", ""),
            "operating_system": self.context_snapshot.get("operating_system", ""),
            "platform": self.context_snapshot.get("platform", ""),
            
            # Temporal info
            "published_date": self.context_snapshot.get("published_date", ""),
            "last_modified_date": self.context_snapshot.get("last_modified_date", ""),
            
            # References
            "references": self.context_snapshot.get("references", [])
        }
        
        # Clean up empty values but preserve empty arrays for required fields
        cleaned = {}
        for k, v in normalized.items():
            if k.endswith('_versions') or k == 'affected_platforms' or k == 'references':
                # Always include these arrays even if empty
                cleaned[k] = v if isinstance(v, list) else []
            elif v not in [None, "", {}, False]:
                cleaned[k] = v
        
        return cleaned
    
    def _extract_version_array(self, field_name: str) -> List[str]:
        """Extract version array from context snapshot."""
        value = self.context_snapshot.get(field_name, "")
        if isinstance(value, list):
            return value
        elif isinstance(value, str) and value:
            # Try to parse version string into array
            # Handle common patterns: "1.0.0 to 1.2.0", "<=2.0.0", "1.0.0, 1.1.0"
            versions = []
            if ' to ' in value or ' through ' in value:
                # Range pattern
                versions = [value]
            elif ',' in value:
                # List pattern
                versions = [v.strip() for v in value.split(',')]
            else:
                # Single version
                versions = [value] if value else []
            return versions
        return []
    
    def _extract_affected_platforms(self) -> List[str]:
        """Extract affected platforms from context snapshot."""
        platforms = []
        
        # Check explicit platform field
        platform_field = self.context_snapshot.get("platform", "")
        if platform_field:
            platforms.append(platform_field)
        
        # Check OS field
        os_field = self.context_snapshot.get("operating_system", "")
        if os_field:
            platforms.append(os_field)
        
        # Extract from description
        description = self.context_snapshot.get("description", "").lower()
        platform_keywords = {
            "Linux": ["linux", "ubuntu", "debian", "centos", "redhat", "fedora", "rhel"],
            "Windows": ["windows", "microsoft", "win32", "win64"],
            "macOS": ["macos", "mac os", "apple", "os x"],
            "Android": ["android"],
            "iOS": ["ios", "iphone", "ipad"]
        }
        
        for platform_name, keywords in platform_keywords.items():
            if any(keyword in description for keyword in keywords):
                if platform_name not in platforms:
                    platforms.append(platform_name)
        
        # Deduplicate
        return list(set(platforms))
    '''
    
    return normalization_code

if __name__ == "__main__":
    print("Canonical Prompt Template v1.2.0")
    print("=" * 50)
    print(f"System block length: {len(CANONICAL_SYSTEM_BLOCK)}")
    print(f"Instruction block length: {len(CANONICAL_INSTRUCTION_BLOCK)}")
    print(f"Workflow block length: {len(CANONICAL_WORKFLOW_BLOCK)}")
    print(f"Output schema block length: {len(CANONICAL_OUTPUT_SCHEMA_BLOCK)}")
    print(f"\nCanonical context fields defined: {len(CANONICAL_CONTEXT_FIELDS)}")
    print("\nKey changes from v1.1.0:")
    print("1. Aligned with canonical playbook schema v0.1.0")
    print("2. Added anti-generic enforcement rules")
    print("3. Added workflow type guidance")
    print("4. Enhanced context field extraction")
    print("5. Structured output schema with hierarchical workflows")