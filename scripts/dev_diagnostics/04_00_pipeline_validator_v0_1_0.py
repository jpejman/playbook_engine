#!/usr/bin/env python3
"""
Playbook Engine Pipeline Validator
Version: v0.1.0
Timestamp: 2026-04-08

Minimal, deterministic, end-to-end pipeline test harness for the Playbook Engine.
Validates: queue → retrieval → generation → QA → approval
"""

import os
import sys
import json
import psycopg2
from psycopg2.extras import Json
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_conn, fetch_one, fetch_all, execute, execute_returning, get_current_database_name, assert_expected_database


class PipelineValidator:
    """Validates the complete playbook engine pipeline."""
    
    # Standardized data payloads
    CVE_ID = "CVE-TEST-0001"
    
    RETRIEVAL_DOC = {
        "doc_id": "doc-1",
        "content": "Test vulnerability context",
        "metadata": {"source": "pipeline_test"},
        "score": 0.95,
        "rank": 1,
        "source_index": "test_index"
    }
    
    GENERATION_PAYLOAD = {
        "model_name": "test-model",
        "prompt_inputs": {},
        "raw_response": "test raw output",
        "parsed_response": {},
        "status": "completed"
    }
    
    QA_PAYLOAD = {
        "qa_score": 0.95,
        "qa_feedback": {"note": "test pass"}
    }
    
    PLAYBOOK = {
        "steps": ["step1", "step2"]
    }
    
    def __init__(self):
        """Initialize the validator."""
        self.results = {}
        self.errors = []
        
    def get_table_columns(self, conn, table_name: str) -> List[str]:
        """Dynamically inspect table columns."""
        query = """
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name = %s
        ORDER BY ordinal_position
        """
        with conn.cursor() as cur:
            cur.execute(query, (table_name,))
            return [row[0] for row in cur.fetchall()]
    
    def validate_step(self, step_name: str, success: bool, result: Any = None):
        """Record validation step result."""
        self.results[step_name] = {
            "success": success,
            "result": result
        }
        if not success:
            self.errors.append(f"{step_name} failed")
    
    def run_pipeline(self):
        """Execute the complete pipeline validation."""
        print("PIPELINE VALIDATOR v0.1.0")
        print("=" * 50)
        
        try:
            # Database verification
            current_db = get_current_database_name()
            print(f"CURRENT_DATABASE: {current_db}")
            assert_expected_database('playbook_engine')
            
            # Use context-managed connection as required
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # Clean up any existing test data first
                    print("\n0. Cleaning up existing test data...")
                    # Check if approved_playbooks has cve_id column
                    columns = self.get_table_columns(conn, "approved_playbooks")
                    if 'cve_id' in columns:
                        cur.execute("DELETE FROM approved_playbooks WHERE cve_id = %s OR generation_run_id IN (SELECT id FROM generation_runs WHERE cve_id = %s)", (self.CVE_ID, self.CVE_ID))
                    else:
                        cur.execute("DELETE FROM approved_playbooks WHERE generation_run_id IN (SELECT id FROM generation_runs WHERE cve_id = %s)", (self.CVE_ID,))
                    
                    cur.execute("DELETE FROM qa_runs WHERE generation_run_id IN (SELECT id FROM generation_runs WHERE cve_id = %s)", (self.CVE_ID,))
                    cur.execute("DELETE FROM generation_runs WHERE cve_id = %s", (self.CVE_ID,))
                    cur.execute("DELETE FROM retrieval_documents WHERE retrieval_run_id IN (SELECT id FROM retrieval_runs WHERE cve_id = %s)", (self.CVE_ID,))
                    cur.execute("DELETE FROM retrieval_runs WHERE cve_id = %s", (self.CVE_ID,))
                    cur.execute("DELETE FROM cve_queue WHERE cve_id = %s", (self.CVE_ID,))
                    print("   [OK] Cleanup completed")
                    
                    # Step 1: Insert CVE into queue
                    print("\n1. Inserting CVE into queue...")
                    cur.execute("""
                        INSERT INTO cve_queue (cve_id, status, priority)
                        VALUES (%s, 'pending', 1)
                        RETURNING id
                    """, (self.CVE_ID,))
                    cve_queue_id = cur.fetchone()[0]
                    self.validate_step("cve_queue_insert", cve_queue_id is not None, cve_queue_id)
                    print(f"   [OK] CVE queue ID: {cve_queue_id}")
                    
                    # Step 2: Create retrieval_run with dynamic column inspection
                    print("\n2. Creating retrieval_run...")
                    columns = self.get_table_columns(conn, "retrieval_runs")
                    print(f"   Found columns: {columns}")
                    
                    # Build insert based on available columns
                    if 'cve_id' not in columns:
                        raise ValueError("Required column 'cve_id' not found in retrieval_runs")
                    
                    columns_to_insert = []
                    values = []
                    
                    # Required column
                    columns_to_insert.append('cve_id')
                    values.append(self.CVE_ID)
                    
                    # Optional column
                    if 'retrieval_type' in columns:
                        columns_to_insert.append('retrieval_type')
                        values.append("test_retrieval")
                    
                    # Build dynamic SQL
                    placeholders = ', '.join(['%s'] * len(values))
                    column_list = ', '.join(columns_to_insert)
                    
                    cur.execute(f"""
                        INSERT INTO retrieval_runs ({column_list})
                        VALUES ({placeholders})
                        RETURNING id
                    """, tuple(values))
                    retrieval_run_id = cur.fetchone()[0]
                    self.validate_step("retrieval_run_insert", retrieval_run_id is not None, retrieval_run_id)
                    print(f"   [OK] Retrieval run ID: {retrieval_run_id}")
                    
                    # Step 3: Insert retrieval_documents with dynamic column mapping
                    print("\n3. Inserting retrieval_documents...")
                    columns = self.get_table_columns(conn, "retrieval_documents")
                    print(f"   Found columns: {columns}")
                    
                    if 'retrieval_run_id' not in columns:
                        raise ValueError("Required column 'retrieval_run_id' not found in retrieval_documents")
                    
                    columns_to_insert = []
                    values = []
                    
                    # Required column
                    columns_to_insert.append('retrieval_run_id')
                    values.append(retrieval_run_id)
                    
                    # Map possible column names from RETRIEVAL_DOC
                    column_mappings = {
                        'doc_id': ['doc_id', 'document_id'],
                        'content': ['content', 'document_text'],
                        'metadata': ['metadata', 'document_metadata'],
                        'source_index': ['source_index'],
                        'score': ['score'],
                        'rank': ['rank']
                    }
                    
                    # Add mapped columns if they exist in the table
                    for doc_key, possible_columns in column_mappings.items():
                        for col_name in possible_columns:
                            if col_name in columns:
                                columns_to_insert.append(col_name)
                                if doc_key == 'metadata':
                                    values.append(Json(self.RETRIEVAL_DOC.get(doc_key, {})))
                                else:
                                    values.append(self.RETRIEVAL_DOC.get(doc_key, None))
                                break
                    
                    # Build dynamic SQL
                    placeholders = ', '.join(['%s'] * len(values))
                    column_list = ', '.join(columns_to_insert)
                    
                    cur.execute(f"""
                        INSERT INTO retrieval_documents ({column_list})
                        VALUES ({placeholders})
                        RETURNING id
                    """, tuple(values))
                    retrieval_doc_id = cur.fetchone()[0]
                    self.validate_step("retrieval_doc_insert", retrieval_doc_id is not None, retrieval_doc_id)
                    print(f"   [OK] Retrieval document ID: {retrieval_doc_id}")
                    
                    # Step 4: Create generation_run with dynamic column inspection
                    print("\n4. Creating generation_run...")
                    columns = self.get_table_columns(conn, "generation_runs")
                    print(f"   Found columns: {columns}")
                    
                    # Check for required columns based on actual schema
                    required_cols = ['cve_id', 'prompt', 'status']
                    missing_cols = [col for col in required_cols if col not in columns]
                    if missing_cols:
                        raise ValueError(f"Missing required columns in generation_runs: {missing_cols}")
                    
                    # Insert generation run - include all available optional columns
                    columns_to_insert = []
                    values = []
                    
                    # Required columns
                    columns_to_insert.extend(['cve_id', 'prompt', 'status'])
                    values.extend([
                        self.CVE_ID,
                        "test rendered prompt",
                        self.GENERATION_PAYLOAD["status"]
                    ])
                    
                    # Optional columns if they exist
                    if 'model' in columns:
                        columns_to_insert.append('model')
                        values.append(self.GENERATION_PAYLOAD["model_name"])
                    
                    if 'response' in columns:
                        columns_to_insert.append('response')
                        values.append(self.GENERATION_PAYLOAD["raw_response"])
                    
                    # Build dynamic SQL
                    placeholders = ', '.join(['%s'] * len(values))
                    column_list = ', '.join(columns_to_insert)
                    
                    cur.execute(f"""
                        INSERT INTO generation_runs ({column_list})
                        VALUES ({placeholders})
                        RETURNING id
                    """, tuple(values))
                    generation_run_id = cur.fetchone()[0]
                    self.validate_step("generation_run_insert", generation_run_id is not None, generation_run_id)
                    print(f"   [OK] Generation run ID: {generation_run_id}")
                    
                    # Step 5: Insert QA run
                    print("\n5. Inserting QA run...")
                    cur.execute("""
                        INSERT INTO qa_runs (
                            generation_run_id,
                            qa_result,
                            qa_score,
                            qa_feedback
                        )
                         VALUES (%s, 'approved', %s, %s)
                        RETURNING id
                    """, (
                        generation_run_id,
                        self.QA_PAYLOAD["qa_score"],
                        Json(self.QA_PAYLOAD["qa_feedback"])
                    ))
                    qa_run_id = cur.fetchone()[0]
                    self.validate_step("qa_run_insert", qa_run_id is not None, qa_run_id)
                    print(f"   [OK] QA run ID: {qa_run_id}")
                    
                    # Step 6: Insert approved_playbook with dynamic column inspection
                    print("\n6. Inserting approved_playbook...")
                    columns = self.get_table_columns(conn, "approved_playbooks")
                    print(f"   Found columns: {columns}")
                    
                    # Check for required columns
                    required_cols = ['playbook', 'version']
                    missing_cols = [col for col in required_cols if col not in columns]
                    if missing_cols:
                        raise ValueError(f"Missing required columns in approved_playbooks: {missing_cols}")
                    
                    # Insert approved playbook
                    columns_to_insert = []
                    values = []
                    
                    # Required columns
                    columns_to_insert.extend(['playbook', 'version'])
                    values.extend([
                        Json(self.PLAYBOOK),
                        1
                    ])
                    
                    # Optional columns
                    if 'generation_run_id' in columns:
                        columns_to_insert.append('generation_run_id')
                        values.append(generation_run_id)
                    
                    if 'cve_id' in columns:
                        columns_to_insert.append('cve_id')
                        values.append(self.CVE_ID)
                    
                    # Build dynamic SQL
                    placeholders = ', '.join(['%s'] * len(values))
                    column_list = ', '.join(columns_to_insert)
                    
                    cur.execute(f"""
                        INSERT INTO approved_playbooks ({column_list})
                        VALUES ({placeholders})
                        RETURNING id
                    """, tuple(values))
                    approved_playbook_id = cur.fetchone()[0]
                    self.validate_step("approved_playbook_insert", approved_playbook_id is not None, approved_playbook_id)
                    print(f"   [OK] Approved playbook ID: {approved_playbook_id}")
                    
                    # Commit all changes
                    conn.commit()
                    
                    # Step 7: Post-run lineage validation
                    print("\n7. Validating lineage chain...")
                    lineage_query = """
                    SELECT
                        q.cve_id,
                        rr.id AS retrieval_run_id,
                        gr.id AS generation_run_id,
                        qr.id AS qa_run_id,
                        ap.id AS approved_playbook_id
                    FROM cve_queue q
                    LEFT JOIN retrieval_runs rr
                        ON rr.cve_id = q.cve_id
                    LEFT JOIN generation_runs gr
                        ON gr.cve_id = q.cve_id
                    LEFT JOIN qa_runs qr
                        ON qr.generation_run_id = gr.id
                    LEFT JOIN approved_playbooks ap
                        ON ap.generation_run_id = gr.id
                    WHERE q.cve_id = %s;
                    """
                    
                    cur.execute(lineage_query, (self.CVE_ID,))
                    lineage_result = cur.fetchone()
                    
                    if not lineage_result:
                        raise ValueError("Lineage validation query returned no results")
                    
                    # Extract results
                    lineage_cve_id = lineage_result[0]
                    lineage_retrieval_run_id = lineage_result[1]
                    lineage_generation_run_id = lineage_result[2]
                    lineage_qa_run_id = lineage_result[3]
                    lineage_approved_playbook_id = lineage_result[4]
                    
                    # Validate all required IDs are present
                    validation_errors = []
                    if not lineage_cve_id:
                        validation_errors.append("cve_id is null")
                    if not lineage_retrieval_run_id:
                        validation_errors.append("retrieval_run_id is null")
                    if not lineage_generation_run_id:
                        validation_errors.append("generation_run_id is null")
                    if not lineage_qa_run_id:
                        validation_errors.append("qa_run_id is null")
                    if not lineage_approved_playbook_id:
                        validation_errors.append("approved_playbook_id is null")
                    
                    # Store lineage validation results
                    self.results["lineage_validation"] = {
                        "cve_id": lineage_cve_id,
                        "retrieval_run_id": lineage_retrieval_run_id,
                        "generation_run_id": lineage_generation_run_id,
                        "qa_run_id": lineage_qa_run_id,
                        "approved_playbook_id": lineage_approved_playbook_id,
                        "valid": len(validation_errors) == 0,
                        "errors": validation_errors
                    }
                    
                    # Print lineage validation results
                    print("\nLINEAGE VALIDATION")
                    print("-" * 50)
                    print(f"cve_id: {lineage_cve_id}")
                    print(f"retrieval_run_id: {lineage_retrieval_run_id}")
                    print(f"generation_run_id: {lineage_generation_run_id}")
                    print(f"qa_run_id: {lineage_qa_run_id}")
                    print(f"approved_playbook_id: {lineage_approved_playbook_id}")
                    print(f"\nLINEAGE STATUS: {'VALID' if len(validation_errors) == 0 else 'INVALID'}")
                    
                    if validation_errors:
                        raise ValueError(f"Lineage validation failed: {', '.join(validation_errors)}")
                    
                    # Store final results
                    self.results["final_ids"] = {
                        "cve_queue_id": cve_queue_id,
                        "retrieval_run_id": retrieval_run_id,
                        "retrieval_doc_id": retrieval_doc_id,
                        "generation_run_id": generation_run_id,
                        "qa_run_id": qa_run_id,
                        "approved_playbook_id": approved_playbook_id
                    }
                    
        except Exception as e:
            print(f"\n[ERROR] Pipeline validation failed: {e}")
            self.errors.append(str(e))
            return False
        
        return len(self.errors) == 0 if isinstance(self.errors, list) else False
    
    def print_results(self):
        """Print validation results."""
        print("\n" + "=" * 50)
        print("PIPELINE EXECUTION RESULT")
        print("-" * 50)
        
        if "final_ids" in self.results:
            ids = self.results["final_ids"]
            for key, value in ids.items():
                print(f"{key}: {value}")
        
        print(f"\nSTATUS: {'SUCCESS' if len(self.errors) == 0 else 'FAILURE'}")
        
        if self.errors:
            print("\nErrors:")
            for error in self.errors:
                print(f"  - {error}")
        
        print("=" * 50)


def check_qa_results_table(conn):
    """Check if qa_results table exists and can be safely removed."""
    try:
        with conn.cursor() as cur:
            # Check if table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'qa_results'
                )
            """)
            exists = cur.fetchone()[0]
            
            if exists:
                # Check if table is empty
                cur.execute("SELECT COUNT(*) FROM qa_results")
                count = cur.fetchone()[0]
                
                # Check for foreign key references
                cur.execute("""
                    SELECT tc.table_name, kcu.column_name
                    FROM information_schema.table_constraints AS tc
                    JOIN information_schema.key_column_usage AS kcu
                      ON tc.constraint_name = kcu.constraint_name
                    JOIN information_schema.constraint_column_usage AS ccu
                      ON ccu.constraint_name = tc.constraint_name
                    WHERE tc.constraint_type = 'FOREIGN KEY'
                      AND tc.table_schema = 'public'
                      AND ccu.table_name = 'qa_results'
                """)
                references = cur.fetchall()
                
                return {
                    "exists": True,
                    "row_count": count,
                    "references": references,
                    "can_remove": count == 0 and len(references) == 0
                }
            else:
                return {"exists": False, "can_remove": False}
    except Exception as e:
        return {"exists": False, "error": str(e), "can_remove": False}


def main():
    """Main validation function."""
    validator = PipelineValidator()
    
    # Test database connection first
    try:
        with get_conn() as conn:
            print("Database connection successful")
    except Exception as e:
        print(f"Failed to connect to database: {e}")
        sys.exit(1)
    
    # Run pipeline validation
    success = validator.run_pipeline()
    
    # Print results
    validator.print_results()
    
    # Optional: Check qa_results table
    try:
        with get_conn() as conn:
            qa_check = check_qa_results_table(conn)
            if qa_check.get("exists") and qa_check.get("can_remove"):
                print("\nOptional cleanup: qa_results table exists and can be removed")
                print(f"  - Row count: {qa_check.get('row_count', 0)}")
                print(f"  - Foreign key references: {len(qa_check.get('references', []))}")
    except Exception as e:
        print(f"\nNote: Could not check qa_results table: {e}")
    
    # Exit with appropriate code
    if success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()