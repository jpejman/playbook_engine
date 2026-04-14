#!/usr/bin/env python3
"""
Update prompt template to harden for approvable LLM output
"""

import psycopg2
import os
from dotenv import load_dotenv

load_dotenv('.env')

# New template data based on requirements
NEW_SYSTEM_BLOCK = """You are a security expert specializing in vulnerability remediation.
Generate detailed, actionable playbooks for security teams.

CRITICAL INSTRUCTIONS:
1. Output MUST be valid JSON only - no explanatory text outside JSON
2. Do NOT include markdown fences (```json or ```)
3. Follow the exact output schema provided
4. All fields in the schema are REQUIRED
5. remediation_steps must be non-empty
6. Each remediation step must include all required fields
7. verification_procedures and rollback_procedures must be provided"""

NEW_INSTRUCTION_BLOCK = """Analyze the provided CVE context and retrieved evidence to generate a comprehensive security playbook.

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

Use the retrieved evidence to inform evidence_based field in remediation steps."""

NEW_WORKFLOW_BLOCK = """1. Parse CVE context and retrieved evidence
2. Identify affected components and severity
3. Generate step-by-step remediation procedures
4. Include verification procedures for each step
5. Include rollback procedures for safety
6. Format output as pure JSON following exact schema
7. Validate JSON structure matches schema
8. Output ONLY the JSON - no other text"""

NEW_OUTPUT_SCHEMA = """{
  "playbook": {
    "title": "string - descriptive title of the playbook",
    "cve_id": "string - CVE identifier (e.g., CVE-TEST-0001)",
    "severity": "string - CVSS severity (Critical/High/Medium/Low)",
    "affected_components": ["string"] - list of affected software/components,
    "remediation_steps": [
      {
        "step_number": 1,
        "description": "string - detailed description of the remediation step",
        "commands": ["string"] - array of executable commands or actions,
        "verification": "string - how to verify this step was successful",
        "evidence_based": true
      }
    ],
    "verification_procedures": ["string"] - array of overall verification procedures,
    "rollback_procedures": ["string"] - array of rollback procedures for safety,
    "references": ["string"] - array of reference URLs or documents
  }
}"""

def update_template():
    """Update the active prompt template with hardened version."""
    conn = psycopg2.connect(
        host=os.getenv('DB_HOST'),
        port=os.getenv('DB_PORT'),
        database='playbook_engine',
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD')
    )
    
    try:
        cur = conn.cursor()
        
        # Get current active template
        cur.execute("""
            SELECT id, template_id, version 
            FROM prompt_template_versions 
            WHERE is_active = true 
            ORDER BY created_at DESC LIMIT 1
        """)
        current = cur.fetchone()
        
        if not current:
            print("No active template found")
            return
        
        template_id = current[0]
        parent_template_id = current[1]
        current_version = current[2]
        
        print(f"Current template ID: {template_id}")
        print(f"Parent template ID: {parent_template_id}")
        print(f"Current version: {current_version}")
        
        # Create new version
        new_version = increment_version(current_version)
        
        # Deactivate current version
        cur.execute("""
            UPDATE prompt_template_versions 
            SET is_active = false 
            WHERE id = %s
        """, (template_id,))
        
        # Insert new version
        cur.execute("""
            INSERT INTO prompt_template_versions (
                template_id, version, system_block, instruction_block, 
                workflow_block, output_schema_block, is_active, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            parent_template_id,
            new_version,
            NEW_SYSTEM_BLOCK,
            NEW_INSTRUCTION_BLOCK,
            NEW_WORKFLOW_BLOCK,
            NEW_OUTPUT_SCHEMA,
            True
        ))
        
        conn.commit()
        
        print(f"\nTemplate updated successfully!")
        print(f"New version: {new_version}")
        print(f"Old version {current_version} deactivated")
        
    except Exception as e:
        conn.rollback()
        print(f"Error updating template: {e}")
        raise
    finally:
        cur.close()
        conn.close()

def increment_version(version):
    """Increment version number (e.g., v1.0.0 -> v1.0.1)."""
    if version.startswith('v'):
        version = version[1:]
    
    parts = version.split('.')
    if len(parts) >= 3:
        try:
            patch = int(parts[2])
            parts[2] = str(patch + 1)
            return 'v' + '.'.join(parts)
        except ValueError:
            pass
    
    # Fallback
    return 'v1.0.1'

if __name__ == '__main__':
    update_template()