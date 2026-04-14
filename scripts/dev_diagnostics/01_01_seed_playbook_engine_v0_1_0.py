#!/usr/bin/env python3
"""
Playbook Engine Seed Script
Version: v0.1.0
Timestamp: 2026-04-08

Inserts minimum required data to support real generation.
Seed objects:
- One prompt template
- One active prompt template version
- One context snapshot for CVE-TEST-0001
"""

import os
import sys
import json
from pathlib import Path
import psycopg2.extras

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client, assert_expected_database


class PlaybookEngineSeeder:
    """Seed required data for playbook engine."""
    
    def __init__(self):
        self.db = get_database_client()
        self.inserted_ids = {}
        
    def seed_prompt_template(self):
        """Insert a prompt template."""
        print("Seeding prompt template...")
        
        # Check if template already exists
        existing = self.db.fetch_one(
            "SELECT id FROM prompt_templates WHERE name = %s AND version = %s",
            ("default_playbook_template", "1.0.0")
        )
        
        if existing:
            print(f"  Template already exists with ID: {existing['id']}")
            self.inserted_ids['template_id'] = existing['id']
            return existing['id']
        
        # Insert new template
        template_content = """# Playbook Generation Template
Generate a comprehensive security playbook for the given CVE."""
        
        # Use transaction for template insertion
        with self.db.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO prompt_templates (name, version, template)
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    ("default_playbook_template", "1.0.0", template_content)
                )
                result = cur.fetchone()
                conn.commit()
        
        template_id = result['id']
        print(f"  Created template with ID: {template_id}")
        self.inserted_ids['template_id'] = template_id
        return template_id
    
    def seed_prompt_template_version(self, template_id):
        """Insert an active prompt template version."""
        print("Seeding prompt template version...")
        
        # Check if active version already exists for this template
        existing = self.db.fetch_one(
            "SELECT id FROM prompt_template_versions WHERE template_id = %s AND is_active = true",
            (template_id,)
        )
        
        if existing:
            print(f"  Active version already exists with ID: {existing['id']}")
            self.inserted_ids['template_version_id'] = existing['id']
            return existing['id']
        
        # Insert new version
        system_block = """You are a security expert specializing in vulnerability remediation.
Generate detailed, actionable playbooks for security teams."""
        
        instruction_block = """Analyze the provided CVE context and generate a comprehensive security playbook.
The playbook should include:
1. Vulnerability assessment
2. Immediate containment steps
3. Root cause analysis
4. Remediation procedures
5. Verification steps
6. Prevention measures"""
        
        workflow_block = """1. Parse CVE context data
2. Identify affected components
3. Determine exploit vectors
4. Generate step-by-step remediation
5. Include validation steps
6. Format as structured JSON"""
        
        output_schema_block = """{
  "playbook": {
    "title": "string",
    "cve_id": "string",
    "severity": "string",
    "affected_components": ["string"],
    "steps": [
      {
        "step_number": "integer",
        "action": "string",
        "description": "string",
        "expected_outcome": "string"
      }
    ],
    "verification": ["string"],
    "references": ["string"]
  }
}"""
        
        # Use transaction for template version insertion
        with self.db.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO prompt_template_versions (
                        template_id, version, system_block, instruction_block,
                        workflow_block, output_schema_block, is_active
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        template_id, "1.0.0", system_block, instruction_block,
                        workflow_block, output_schema_block, True
                    )
                )
                result = cur.fetchone()
                conn.commit()
        
        version_id = result['id']
        print(f"  Created template version with ID: {version_id}")
        self.inserted_ids['template_version_id'] = version_id
        return version_id
    
    def seed_cve_context_snapshot(self):
        """Insert a context snapshot for CVE-TEST-0001."""
        print("Seeding CVE context snapshot...")
        
        # Check if snapshot already exists
        existing = self.db.fetch_one(
            "SELECT id FROM cve_context_snapshot WHERE cve_id = %s",
            ("CVE-TEST-0001",)
        )
        
        if existing:
            print(f"  Context snapshot already exists with ID: {existing['id']}")
            self.inserted_ids['context_snapshot_id'] = existing['id']
            return existing['id']
        
        # Create context data
        context_data = {
            "cve_id": "CVE-TEST-0001",
            "description": "Test CVE for Playbook Engine run 1",
            "cvss_score": 7.5,
            "cwe": "CWE-79",
            "affected_products": ["test-product"],
            "references": ["https://example.local/test-cve"],
            "vulnerability_type": "Cross-site Scripting (XSS)",
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "Required",
            "scope": "Changed",
            "confidentiality_impact": "Low",
            "integrity_impact": "Low",
            "availability_impact": "None",
            "published_date": "2026-04-08",
            "last_modified_date": "2026-04-08"
        }
        
        # Use transaction for context snapshot insertion
        with self.db.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO cve_context_snapshot (cve_id, context_data, confidence_score)
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    ("CVE-TEST-0001", json.dumps(context_data), 0.95)
                )
                result = cur.fetchone()
                conn.commit()
        
        snapshot_id = result['id']
        print(f"  Created context snapshot with ID: {snapshot_id}")
        self.inserted_ids['context_snapshot_id'] = snapshot_id
        return snapshot_id
    
    def seed_cve_queue_item(self):
        """Optionally seed a CVE queue item if needed."""
        print("Checking CVE queue...")
        
        # Check if CVE already in queue
        existing = self.db.fetch_one(
            "SELECT id FROM cve_queue WHERE cve_id = %s",
            ("CVE-TEST-0001",)
        )
        
        if existing:
            print(f"  CVE already in queue with ID: {existing['id']}")
            self.inserted_ids['queue_id'] = existing['id']
            return existing['id']
        
        # Use transaction for queue insertion
        with self.db.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO cve_queue (cve_id, status, priority)
                    VALUES (%s, 'pending', 1)
                    RETURNING id
                    """,
                    ("CVE-TEST-0001",)
                )
                result = cur.fetchone()
                conn.commit()
        
        queue_id = result['id']
        print(f"  Created queue item with ID: {queue_id}")
        self.inserted_ids['queue_id'] = queue_id
        return queue_id
    
    def run_seeding(self):
        """Execute all seeding operations."""
        print("PLAYBOOK ENGINE SEEDER v0.1.0")
        print("=" * 50)
        
        try:
            # Verify database target
            assert_expected_database('playbook_engine')
            
            # Seed data
            template_id = self.seed_prompt_template()
            version_id = self.seed_prompt_template_version(template_id)
            snapshot_id = self.seed_cve_context_snapshot()
            queue_id = self.seed_cve_queue_item()
            
            print("\n" + "=" * 50)
            print("SEEDING COMPLETE")
            print("-" * 50)
            print(f"Template ID: {template_id}")
            print(f"Template Version ID: {version_id}")
            print(f"Context Snapshot ID: {snapshot_id}")
            print(f"Queue ID: {queue_id}")
            print("=" * 50)
            
            return True
            
        except Exception as e:
            print(f"\n[ERROR] Seeding failed: {e}")
            return False


def main():
    """Main seeding function."""
    seeder = PlaybookEngineSeeder()
    success = seeder.run_seeding()
    
    if success:
        print("\nSeeding successful!")
        sys.exit(0)
    else:
        print("\nSeeding failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()