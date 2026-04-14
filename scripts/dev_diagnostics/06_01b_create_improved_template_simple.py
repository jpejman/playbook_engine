#!/usr/bin/env python3
"""
Create Improved Prompt Template Version v1.1.0 - Simple Version
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

# Improved template blocks (shorter versions for testing)
IMPROVED_SYSTEM_BLOCK = """You are a security analyst specializing in vulnerability remediation.
Generate detailed, actionable playbooks for security teams.

CRITICAL: Output MUST be valid JSON only - no explanatory text outside JSON.
Follow the exact output schema provided."""

IMPROVED_INSTRUCTION_BLOCK = """Analyze the CVE context and retrieved evidence to generate a security playbook.

REQUIREMENTS:
1. Output MUST be pure JSON following the exact schema
2. All fields in the schema are REQUIRED
3. remediation_steps must contain at least one step
4. Include verification_procedures and rollback_procedures

Consider affected OS, software, package, and versions when generating remediation steps."""

IMPROVED_WORKFLOW_BLOCK = """1. Analyze CVE context
2. Review retrieved evidence
3. Generate step-by-step remediation procedures
4. Include verification and rollback procedures
5. Format output as pure JSON
6. Output ONLY the JSON"""

IMPROVED_OUTPUT_SCHEMA_BLOCK = """{
  "playbook": {
    "title": "string",
    "cve_id": "string",
    "severity": "string",
    "retrieval_metadata": {
      "decision": "string",
      "evidence_count": "integer",
      "source_indexes": ["string"]
    },
    "affected_components": ["string"],
    "vulnerability_context": {
      "affected_os": "string",
      "affected_software": "string",
      "affected_versions": "string",
      "vulnerability_type": "string"
    },
    "remediation_steps": [
      {
        "step_number": 1,
        "description": "string",
        "commands": ["string"],
        "verification": "string",
        "evidence_based": true
      }
    ],
    "verification_procedures": ["string"],
    "rollback_procedures": ["string"],
    "references": ["string"]
  }
}"""

def main():
    """Main function."""
    logger.info("Creating improved prompt template v1.1.0 (simple version)")
    
    try:
        db = DatabaseClient()
        
        # First, deactivate all existing versions
        deactivate_sql = """
        UPDATE prompt_template_versions
        SET is_active = FALSE
        WHERE template_id = 2
        """
        db.execute(deactivate_sql)
        logger.info("Deactivated all existing versions")
        
        # Insert new version
        insert_sql = """
        INSERT INTO prompt_template_versions (
            template_id, version, system_block,
            instruction_block, workflow_block, output_schema_block, is_active
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """
        
        result = db.fetch_one(insert_sql, (
            2,  # template_id
            'v1.1.0',
            IMPROVED_SYSTEM_BLOCK,
            IMPROVED_INSTRUCTION_BLOCK,
            IMPROVED_WORKFLOW_BLOCK,
            IMPROVED_OUTPUT_SCHEMA_BLOCK,
            True
        ))
        
        if result:
            version_id = result['id']
            logger.info(f"Successfully created version v1.1.0 with ID: {version_id}")
            
            # Verify
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
                
        else:
            logger.error("Failed to insert new version")
            
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
    else:
        logger.error("Failed to create improved template")
        sys.exit(1)