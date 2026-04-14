#!/usr/bin/env python3
"""
Create Improved Prompt Template Version v1.1.0
Version: v1.1.0
Timestamp: 2026-04-08

Creates a new improved prompt template version based on the user's 2 better examples
and richer NVD/CVE context fields.
"""

import sys
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

# Note: We're not using PromptRepository due to schema differences
# from data.repositories.prompt_repo import PromptRepository
from utils.db import DatabaseClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Improved template blocks based on the user's 2 better examples
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

def create_improved_template():
    """Create the improved prompt template version v1.1.0."""
    logger.info("Creating improved prompt template version v1.1.0...")
    
    try:
        # Initialize database client
        db_client = DatabaseClient()
        
        # Get the existing template
        template_name = "default_playbook_template"
        template_sql = """
        SELECT id, name, version, template, created_at
        FROM prompt_templates
        WHERE name = %s
        ORDER BY id DESC
        LIMIT 1
        """
        
        template = db_client.fetch_one(template_sql, (template_name,))
        
        if not template:
            logger.error(f"Template '{template_name}' not found")
            return False
        
        template_id = template['id']
        logger.info(f"Found existing template: ID={template_id}, Name={template['name']}, Current version={template['version']}")
        
        # Create new version v1.1.0 in prompt_template_versions
        # First, get the next version number
        version_sql = """
        SELECT COALESCE(MAX(CAST(version AS INTEGER)), 0) + 1 as next_version
        FROM prompt_template_versions
        WHERE template_id = %s AND version ~ '^[0-9]+$'
        """
        
        version_result = db_client.fetch_one(version_sql, (template_id,))
        if not version_result:
            next_version = 1
        else:
            next_version = version_result['next_version']
        
        # For semantic versioning, we'll use v1.1.0
        semantic_version = "v1.1.0"
        
        # Insert new version
        insert_sql = """
        INSERT INTO prompt_template_versions (
            template_id, version, system_block,
            instruction_block, workflow_block, output_schema_block, is_active
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """
        
        result = db_client.fetch_one(insert_sql, (
            template_id,
            semantic_version,
            IMPROVED_SYSTEM_BLOCK,
            IMPROVED_INSTRUCTION_BLOCK,
            IMPROVED_WORKFLOW_BLOCK,
            IMPROVED_OUTPUT_SCHEMA_BLOCK,
            True  # Set as active
        ))
        
        if result:
            version_id = result['id']
            
            # Deactivate other versions
            deactivate_sql = """
            UPDATE prompt_template_versions
            SET is_active = FALSE
            WHERE template_id = %s AND id != %s
            """
            db_client.execute(deactivate_sql, (template_id, version_id))
            
            logger.info(f"Successfully created improved template version {semantic_version} with ID: {version_id}")
            
            # Verify the creation
            verify_sql = """
            SELECT ptv.id, ptv.version, pt.name, ptv.created_at, ptv.is_active
            FROM prompt_template_versions ptv
            JOIN prompt_templates pt ON ptv.template_id = pt.id
            WHERE ptv.id = %s
            """
            result = db_client.fetch_one(verify_sql, (version_id,))
            
            if result:
                logger.info(f"Verified: Version ID={result['id']}, Version={result['version']}, Template={result['name']}")
                logger.info(f"Active: {result['is_active']}, Created at: {result['created_at']}")
            
            # Show all versions for this template
            versions_sql = """
            SELECT id, version, is_active, created_at
            FROM prompt_template_versions
            WHERE template_id = %s
            ORDER BY created_at DESC
            LIMIT 5
            """
            versions = db_client.fetch_all(versions_sql, (template_id,))
            
            logger.info(f"\nAll versions for template {template_name}:")
            for i, version in enumerate(versions, 1):
                status = "ACTIVE" if version['is_active'] else "inactive"
                logger.info(f"  {i}. ID={version['id']}, Version={version['version']}, Status={status}, Created={version['created_at']}")
            
            return True
        else:
            logger.error("Failed to create template version")
            return False
            
    except Exception as e:
        logger.error(f"Error creating improved template: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if 'db_client' in locals():
            db_client.close_all()

def main():
    """Main function."""
    logger.info("Starting improved prompt template creation (v1.1.0)")
    logger.info("=" * 60)
    
    success = create_improved_template()
    
    if success:
        logger.info("=" * 60)
        logger.info("Improved prompt template v1.1.0 created successfully!")
        logger.info("Key improvements:")
        logger.info("1. Based on user's 2 better prompt examples")
        logger.info("2. Includes richer NVD/CVE context fields")
        logger.info("3. More specific guidance for security analysts")
        logger.info("4. Enhanced output schema with vulnerability_context")
        logger.info("5. Structured workflows with OS/package-specific procedures")
    else:
        logger.error("Failed to create improved prompt template")
        sys.exit(1)

if __name__ == "__main__":
    main()