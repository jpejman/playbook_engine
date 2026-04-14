#!/usr/bin/env python3
"""
Create Improved Prompt Template Version v1.1.0 - Fixed Version
"""

import sys
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from utils.db import DatabaseClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Full improved template blocks
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

def main():
    """Main function."""
    logger.info("Creating improved prompt template v1.1.0 (fixed version)")
    
    try:
        db = DatabaseClient()
        
        # Use execute method which commits
        # First, deactivate all existing versions
        deactivate_sql = """
        UPDATE prompt_template_versions
        SET is_active = FALSE
        WHERE template_id = 2
        """
        db.execute(deactivate_sql)
        logger.info("Deactivated all existing versions")
        
        # Insert new version using execute with fetch=False
        insert_sql = """
        INSERT INTO prompt_template_versions (
            template_id, version, system_block,
            instruction_block, workflow_block, output_schema_block, is_active
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """
        
        # We need to use a cursor directly to get the RETURNING id
        with db.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(insert_sql, (
                    2,  # template_id
                    'v1.1.0',
                    IMPROVED_SYSTEM_BLOCK,
                    IMPROVED_INSTRUCTION_BLOCK,
                    IMPROVED_WORKFLOW_BLOCK,
                    IMPROVED_OUTPUT_SCHEMA_BLOCK,
                    True
                ))
                version_id = cursor.fetchone()[0]
                conn.commit()
                logger.info(f"Successfully created version v1.1.0 with ID: {version_id}")
        
        # Verify using fetch_one (read-only)
        verify_sql = """
        SELECT id, version, is_active, created_at
        FROM prompt_template_versions
        WHERE id = %s
        """
        verify = db.fetch_one(verify_sql, (version_id,))
        
        if verify:
            logger.info(f"Verified: ID={verify['id']}, Version={verify['version']}, Active={verify['is_active']}")
            
        # Show all versions
        versions_sql = """
        SELECT id, version, is_active, created_at
        FROM prompt_template_versions
        WHERE template_id = 2
        ORDER BY id DESC
        LIMIT 5
        """
        versions = db.fetch_all(versions_sql)
        
        logger.info("\nAll versions:")
        for v in versions:
            status = "ACTIVE" if v['is_active'] else "inactive"
            logger.info(f"  ID={v['id']}, Version={v['version']}, Status={status}")
            
    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if 'db' in locals():
            db.close_all()
    
    return True

if __name__ == "__main__":
    success = main()
    if success:
        logger.info("\nImproved template v1.1.0 created successfully!")
        logger.info("Key improvements:")
        logger.info("1. Based on user's 2 better prompt examples")
        logger.info("2. Includes richer NVD/CVE context fields")
        logger.info("3. More specific guidance for security analysts")
        logger.info("4. Enhanced output schema with vulnerability_context")
        logger.info("5. Structured workflows with OS/package-specific procedures")
    else:
        logger.error("Failed to create improved template")
        sys.exit(1)