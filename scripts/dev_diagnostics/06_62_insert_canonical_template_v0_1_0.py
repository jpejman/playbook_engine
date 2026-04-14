#!/usr/bin/env python3
"""
Insert Canonical Prompt Template into Database - Group 6.6
Version: v0.1.0
Timestamp: 2026-04-08

This script inserts the canonical prompt template (v1.2.0) into the database
with proper transaction handling to ensure persistence.
"""

import sys
import os
import json
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.db import DatabaseClient
from canonical_prompt_template_v1_2_0 import get_canonical_template_blocks


def insert_canonical_prompt_template():
    """Insert canonical prompt template into database with transaction."""
    
    print("=" * 80)
    print("INSERT CANONICAL PROMPT TEMPLATE v1.2.0")
    print("=" * 80)
    
    # Get database client
    db = DatabaseClient()
    
    # Get canonical template blocks
    template_blocks = get_canonical_template_blocks()
    
    # Template metadata
    template_name = "canonical_prompt_template_v1_2_0"
    template_version = "1.2.0"
    template_description = "Canonical prompt template aligned with canonical playbook schema v0.1.0. Includes anti-generic enforcement, workflow type guidance, and enhanced context field extraction."
    is_active = True
    
    print(f"Template name: {template_name}")
    print(f"Template version: {template_version}")
    print(f"Description: {template_description[:100]}...")
    print(f"System block length: {len(template_blocks['system_block'])} chars")
    print(f"Instruction block length: {len(template_blocks['instruction_block'])} chars")
    print(f"Workflow block length: {len(template_blocks['workflow_block'])} chars")
    print(f"Output schema block length: {len(template_blocks['output_schema_block'])} chars")
    
    # Check if template already exists
    print("\nChecking for existing template...")
    existing_template = db.fetch_one(
        "SELECT id, version FROM prompt_templates WHERE name = %s",
        (template_name,)
    )
    
    if existing_template:
        print(f"Template already exists with ID: {existing_template['id']}")
        print(f"Existing version: {existing_template['version']}")
        
        # Check if we should update
        if existing_template['version'] == template_version:
            print("Same version already exists. Skipping insertion.")
            return False
        else:
            print(f"Different version exists. Will insert new version.")
    
    # Use transaction for atomic insertion
    print("\nStarting database transaction...")
    conn = db.begin_transaction()
    
    try:
        with conn.cursor() as cursor:
            # Insert into prompt_templates table (simple version)
            insert_template_query = """
            INSERT INTO prompt_templates (
                name, version, template, created_at
            ) VALUES (%s, %s, %s, NOW())
            RETURNING id
            """
            
            # Create a simple template string for the main table
            simple_template = f"Canonical Prompt Template v{template_version}"
            
            cursor.execute(insert_template_query, (
                template_name,
                template_version,
                simple_template
            ))
            
            template_result = cursor.fetchone()
            template_id = template_result[0] if template_result else None
            print(f"Inserted template with ID: {template_id}")
            
            # Insert into prompt_template_versions table for history (with blocks)
            insert_version_query = """
            INSERT INTO prompt_template_versions (
                template_id, version, system_block,
                instruction_block, workflow_block, output_schema_block,
                is_active, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """
            
            cursor.execute(insert_version_query, (
                template_id,
                template_version,
                template_blocks['system_block'],
                template_blocks['instruction_block'],
                template_blocks['workflow_block'],
                template_blocks['output_schema_block'],
                is_active
            ))
            
            print("Inserted version history record")
            
            # Commit transaction
            db.commit_transaction(conn)
            print("Transaction committed successfully!")
            
            # Verify insertion
            print("\nVerifying insertion...")
            verify_query = """
            SELECT id, name, version, created_at 
            FROM prompt_templates 
            WHERE id = %s
            """
            
            result = db.fetch_one(verify_query, (template_id,))
            if result:
                print(f"[OK] Template verified: {result['name']} v{result['version']}")
                print(f"  ID: {result['id']}, Created: {result['created_at']}")
                return True
            else:
                print("[ERROR] Template not found after insertion!")
                return False
                
    except Exception as e:
        print(f"Error during transaction: {e}")
        db.rollback_transaction(conn)
        print("Transaction rolled back.")
        raise


def verify_template_in_database():
    """Verify the template exists in database."""
    
    db = DatabaseClient()
    
    print("\n" + "=" * 80)
    print("VERIFY TEMPLATE IN DATABASE")
    print("=" * 80)
    
    # Check all templates
    all_templates = db.fetch_all(
        "SELECT id, name, version, is_active, created_at FROM prompt_templates ORDER BY created_at DESC"
    )
    
    print(f"Total templates in database: {len(all_templates)}")
    
    for template in all_templates:
        print(f"{template['name']} v{template['version']} (ID: {template['id']})")
    
    # Check canonical template specifically
    canonical_template = db.fetch_one(
        "SELECT id, name, version, is_active, created_at FROM prompt_templates WHERE name = 'canonical_prompt_template_v1_2_0'"
    )
    
    if canonical_template:
        print(f"\n[OK] Canonical template found:")
        print(f"  ID: {canonical_template['id']}")
        print(f"  Version: {canonical_template['version']}")
        print(f"  Created: {canonical_template['created_at']}")
        return True
    else:
        print("\n[ERROR] Canonical template not found!")
        return False


def main():
    """Main execution function."""
    
    print("Group 6.6: Insert Canonical Prompt Template")
    print("=" * 80)
    
    try:
        # Insert template
        success = insert_canonical_prompt_template()
        
        if success:
            # Verify insertion
            verify_template_in_database()
            
            print("\n" + "=" * 80)
            print("SUCCESS: Canonical prompt template v1.2.0 inserted into database")
            print("=" * 80)
            print("\nNext steps:")
            print("1. Update prompt_input_builder.py to use canonical template")
            print("2. Run enhanced queue selector to get new CVE")
            print("3. Run enrichment for the new CVE")
            print("4. Run generation with canonical template")
            print("5. Validate output matches canonical schema")
        else:
            print("\nTemplate insertion skipped or failed.")
            
    except Exception as e:
        print(f"\nERROR: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())