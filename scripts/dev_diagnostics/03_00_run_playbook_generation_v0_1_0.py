#!/usr/bin/env python3
"""
Playbook Engine Run 1 Execution Script (No Vector Retrieval)
Version: v0.1.0
Timestamp: 2026-04-08

Run one real generation cycle with:
- DB input
- Prompt construction  
- LLM call (mock for Run 1)
- DB persistence
- Minimal QA
- No vector retrieval
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client, assert_expected_database
import psycopg2.extras
from psycopg2.extras import Json


class PlaybookGenerator:
    """Run 1 playbook generation without vector retrieval."""
    
    def __init__(self, mode: str = "none"):
        self.db = get_database_client()
        self.cve_id = "CVE-TEST-0001"
        self.mode = mode  # "none" for no retrieval
        self.results = {}
        
    def assert_database_target(self):
        """Assert connected to correct database."""
        print("Verifying database target...")
        assert_expected_database('playbook_engine')
        print("  Connected to playbook_engine")
    
    def load_queue_item(self) -> Optional[Dict]:
        """Load pending queue item for CVE-TEST-0001."""
        print(f"\nLoading queue item for {self.cve_id}...")
        
        queue_item = self.db.fetch_one(
            "SELECT id, cve_id, status FROM cve_queue WHERE cve_id = %s AND status = 'pending'",
            (self.cve_id,)
        )
        
        if queue_item:
            print(f"  Found queue item ID: {queue_item['id']}")
            self.results['queue_id'] = queue_item['id']
            return queue_item
        else:
            print(f"  No pending queue item found for {self.cve_id}")
            return None
    
    def load_context_snapshot(self) -> Dict:
        """Load context snapshot for the CVE."""
        print(f"\nLoading context snapshot for {self.cve_id}...")
        
        snapshot = self.db.fetch_one(
            "SELECT id, cve_id, context_data FROM cve_context_snapshot WHERE cve_id = %s",
            (self.cve_id,)
        )
        
        if not snapshot:
            raise ValueError(f"No context snapshot found for {self.cve_id}")
        
        print(f"  Found context snapshot ID: {snapshot['id']}")
        self.results['context_snapshot_id'] = snapshot['id']
        
        # context_data is already a dict (jsonb column)
        context_data = snapshot['context_data']
        return context_data
    
    def load_active_prompt_template(self) -> Dict:
        """Load active prompt template version."""
        print("\nLoading active prompt template version...")
        
        template_version = self.db.fetch_one(
            """
            SELECT 
                v.id, v.template_id, v.version,
                v.system_block, v.instruction_block,
                v.workflow_block, v.output_schema_block,
                t.name as template_name
            FROM prompt_template_versions v
            JOIN prompt_templates t ON v.template_id = t.id
            WHERE v.is_active = true
            ORDER BY v.created_at DESC
            LIMIT 1
            """
        )
        
        if not template_version:
            raise ValueError("No active prompt template version found")
        
        print(f"  [OK] Found active template version ID: {template_version['id']}")
        print(f"  Template: {template_version['template_name']} v{template_version['version']}")
        self.results['template_version_id'] = template_version['id']
        self.results['template_id'] = template_version['template_id']
        
        return template_version
    
    def render_prompt(self, template_version: Dict, context_data: Dict) -> str:
        """Render prompt from template blocks and context."""
        print("\nRendering prompt...")
        
        # Normalize context data for prompt
        normalized_context = {
            "cve_id": context_data.get("cve_id", ""),
            "description": context_data.get("description", ""),
            "cvss_score": context_data.get("cvss_score", 0),
            "cwe": context_data.get("cwe", ""),
            "affected_products": context_data.get("affected_products", []),
            "vulnerability_type": context_data.get("vulnerability_type", ""),
            "attack_vector": context_data.get("attack_vector", ""),
            "references": context_data.get("references", [])
        }
        
        # Build prompt from template blocks
        prompt_parts = []
        
        if template_version.get('system_block'):
            prompt_parts.append(f"System: {template_version['system_block']}")
        
        if template_version.get('instruction_block'):
            prompt_parts.append(f"Instructions: {template_version['instruction_block']}")
        
        if template_version.get('workflow_block'):
            prompt_parts.append(f"Workflow: {template_version['workflow_block']}")
        
        prompt_parts.append(f"\nContext Data:\n{json.dumps(normalized_context, indent=2)}")
        
        if template_version.get('output_schema_block'):
            prompt_parts.append(f"\nOutput Schema:\n{template_version['output_schema_block']}")
        
        rendered_prompt = "\n\n".join(prompt_parts)
        
        print(f"  [OK] Prompt rendered ({len(rendered_prompt)} chars)")
        self.results['rendered_prompt'] = rendered_prompt
        self.results['prompt_inputs'] = normalized_context
        
        return rendered_prompt
    
    def call_llm_mock(self, prompt: str) -> Dict[str, Any]:
        """Mock LLM call for Run 1 (no external API)."""
        print("\nCalling LLM (mock implementation)...")
        
        # Print LLM configuration being used
        llm_base_url = os.getenv('LLM_BASE_URL', 'https://api.openai.com/v1')
        llm_model = os.getenv('LLM_MODEL', 'gpt-4')
        llm_timeout = os.getenv('REQUEST_TIMEOUT', '30')
        
        print(f"  LLM Configuration:")
        print(f"    Base URL: {llm_base_url}")
        print(f"    Model: {llm_model}")
        print(f"    Timeout: {llm_timeout}s")
        print("  Note: Using mock implementation for Run 1")
        
        # Simulate API call delay
        time.sleep(0.5)
        
        # Generate mock response
        mock_response = {
            "playbook": {
                "title": f"Remediation Playbook for {self.cve_id}",
                "cve_id": self.cve_id,
                "severity": "High",
                "affected_components": ["test-product"],
                "steps": [
                    {
                        "step_number": 1,
                        "action": "Isolate affected systems",
                        "description": "Disconnect vulnerable systems from network",
                        "expected_outcome": "Containment of vulnerability"
                    },
                    {
                        "step_number": 2,
                        "action": "Apply security patches",
                        "description": "Install latest security updates for test-product",
                        "expected_outcome": "Vulnerability patched"
                    },
                    {
                        "step_number": 3,
                        "action": "Validate remediation",
                        "description": "Run security scans to verify fix",
                        "expected_outcome": "Confirmation of successful remediation"
                    }
                ],
                "verification": [
                    "Run vulnerability scan",
                    "Check system logs",
                    "Validate patch installation"
                ],
                "references": ["https://example.local/test-cve"]
            }
        }
        
        raw_response = json.dumps(mock_response, indent=2)
        
        print(f"  [OK] Generated mock response ({len(raw_response)} chars)")
        self.results['raw_response'] = raw_response
        self.results['parsed_response'] = mock_response
        
        return {
            "raw": raw_response,
            "parsed": mock_response,
            "model": llm_model
        }
    
    def persist_generation_run(self, queue_id: Optional[int], template_version_id: int, 
                              prompt: str, context: Dict, llm_result: Dict) -> int:
        """Persist generation run to database."""
        print("\nPersisting generation run...")
        
        with self.db.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # Check what columns exist in generation_runs
                cur.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'generation_runs' 
                    ORDER BY ordinal_position
                """)
                columns = [row['column_name'] for row in cur.fetchall()]
                print(f"  Available columns in generation_runs: {columns}")
                
                # Build insert query based on available columns
                if 'queue_id' in columns and 'prompt_template_version_id' in columns and 'prompt_inputs' in columns:
                    # New schema with all columns
                    cur.execute(
                        """
                        INSERT INTO generation_runs (
                            cve_id, queue_id, prompt_template_version_id,
                            rendered_prompt, prompt_inputs, model_name,
                            raw_response, parsed_response, status
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                        """,
                        (
                            self.cve_id,
                            queue_id,
                            template_version_id,
                            prompt,
                            Json(context),  # Store context as prompt_inputs
                            llm_result['model'],
                            llm_result['raw'],
                            Json(llm_result['parsed']),
                            'completed'
                        )
                    )
                elif 'prompt' in columns and 'response' in columns:
                    # Older schema with prompt and response columns
                    cur.execute(
                        """
                        INSERT INTO generation_runs (
                            cve_id, prompt, response, model, status
                        )
                        VALUES (%s, %s, %s, %s, %s)
                        RETURNING id
                        """,
                        (
                            self.cve_id,
                            prompt,
                            llm_result['raw'],
                            llm_result['model'],
                            'completed'
                        )
                    )
                else:
                    # Minimal schema
                    cur.execute(
                        """
                        INSERT INTO generation_runs (cve_id)
                        VALUES (%s)
                        RETURNING id
                        """,
                        (self.cve_id,)
                    )
                
                result = cur.fetchone()
                conn.commit()
        
        if result and 'id' in result:
            generation_run_id = result['id']
            print(f"  [OK] Created generation run ID: {generation_run_id}")
            self.results['generation_run_id'] = generation_run_id
            return generation_run_id
        else:
            raise ValueError("Failed to get generation run ID from database")
    
    def perform_qa(self, generation_run_id: int, parsed_response: Dict) -> Dict:
        """Perform minimal QA on generated playbook."""
        print("\nPerforming QA...")
        
        # Simple deterministic approval rules
        qa_result = "needs_revision"
        qa_score = 0.0
        qa_feedback = {"errors": []}
        
        # Rule 1: Response exists
        if not parsed_response:
            qa_feedback["errors"].append("No parsed response")
        
        # Rule 2: Contains playbook structure
        elif "playbook" not in parsed_response:
            qa_feedback["errors"].append("Missing 'playbook' key in response")
        
        # Rule 3: Contains steps
        elif "steps" not in parsed_response.get("playbook", {}):
            qa_feedback["errors"].append("Missing 'steps' in playbook")
        
        # Rule 4: Steps is non-empty list
        elif not isinstance(parsed_response["playbook"].get("steps"), list):
            qa_feedback["errors"].append("'steps' is not a list")
        
        elif len(parsed_response["playbook"]["steps"]) == 0:
            qa_feedback["errors"].append("'steps' list is empty")
        
        else:
            # All rules passed
            qa_result = "approved"
            qa_score = 0.95
            qa_feedback = {"note": "Basic validation passed"}
        
        print(f"  QA Result: {qa_result}")
        print(f"  QA Score: {qa_score}")
        
        self.results['qa_result'] = qa_result
        self.results['qa_score'] = qa_score
        self.results['qa_feedback'] = qa_feedback
        
        return {
            "result": qa_result,
            "score": qa_score,
            "feedback": qa_feedback
        }
    
    def persist_qa_run(self, generation_run_id: int, qa_result: Dict) -> int:
        """Persist QA run to database."""
        print("\nPersisting QA run...")
        
        with self.db.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO qa_runs (
                        generation_run_id, qa_result, qa_score, qa_feedback
                    )
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        generation_run_id,
                        qa_result['result'],
                        qa_result['score'],
                        json.dumps(qa_result['feedback'])
                    )
                )
                result = cur.fetchone()
                conn.commit()
        
        if result and 'id' in result:
            qa_run_id = result['id']
            print(f"  [OK] Created QA run ID: {qa_run_id}")
            self.results['qa_run_id'] = qa_run_id
            return qa_run_id
        else:
            raise ValueError("Failed to get QA run ID from database")
    
    def persist_approved_playbook(self, generation_run_id: int, parsed_response: Dict, 
                                 qa_result: str) -> Optional[int]:
        """Persist approved playbook if QA passed."""
        if qa_result != "approved":
            print("\nSkipping approved_playbooks insertion (QA not approved)")
            return None
        
        print("\nPersisting approved playbook...")
        
        with self.db.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # Check what columns exist in approved_playbooks
                cur.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'approved_playbooks' 
                    ORDER BY ordinal_position
                """)
                columns = [row['column_name'] for row in cur.fetchall()]
                print(f"  Available columns in approved_playbooks: {columns}")
                
                # Build insert query based on available columns
                if 'cve_id' in columns and 'generation_run_id' in columns:
                    # New schema with cve_id and generation_run_id
                    cur.execute(
                        """
                        INSERT INTO approved_playbooks (
                            cve_id, generation_run_id, playbook, version
                        )
                        VALUES (%s, %s, %s, %s)
                        RETURNING id
                        """,
                        (
                            self.cve_id,
                            generation_run_id,
                            json.dumps(parsed_response),
                            1
                        )
                    )
                elif 'generation_run_id' in columns and 'playbook' in columns:
                    # Schema with generation_run_id (NOT NULL) and playbook
                    cur.execute(
                        """
                        INSERT INTO approved_playbooks (
                            generation_run_id, playbook
                        )
                        VALUES (%s, %s)
                        RETURNING id
                        """,
                        (
                            generation_run_id,
                            json.dumps(parsed_response)
                        )
                    )
                elif 'playbook' in columns:
                    # Older schema with just playbook
                    cur.execute(
                        """
                        INSERT INTO approved_playbooks (playbook)
                        VALUES (%s)
                        RETURNING id
                        """,
                        (json.dumps(parsed_response),)
                    )
                else:
                    print("  Note: approved_playbooks table not available or missing columns")
                    return None
                
                result = cur.fetchone()
                conn.commit()
        
        if result and 'id' in result:
            approved_playbook_id = result['id']
            print(f"  [OK] Created approved playbook ID: {approved_playbook_id}")
            self.results['approved_playbook_id'] = approved_playbook_id
            return approved_playbook_id
        else:
            print("  [WARNING] Failed to get approved playbook ID")
            return None
    
    def update_queue_status(self, queue_id: Optional[int], status: str):
        """Update queue item status if queue_id exists."""
        if not queue_id:
            return
        
        print(f"\nUpdating queue status to '{status}'...")
        
        self.db.execute(
            "UPDATE cve_queue SET status = %s WHERE id = %s",
            (status, queue_id)
        )
        
        print(f"  [OK] Queue item {queue_id} updated")
    
    def run_generation(self):
        """Execute complete generation flow."""
        print(f"PLAYBOOK ENGINE - RUN 1 ({self.mode.upper()} RETRIEVAL)")
        print("=" * 50)
        
        try:
            # Step A: Assert database target
            self.assert_database_target()
            
            # Step B: Load queue item
            queue_item = self.load_queue_item()
            queue_id = queue_item['id'] if queue_item else None
            
            # Step C: Load context snapshot
            context_data = self.load_context_snapshot()
            
            # Step D: Load active prompt template
            template_version = self.load_active_prompt_template()
            
            # Step E: Render prompt
            prompt = self.render_prompt(template_version, context_data)
            
            # Step F: Call LLM (mock)
            llm_result = self.call_llm_mock(prompt)
            
            # Step G: Persist generation run
            generation_run_id = self.persist_generation_run(
                queue_id, 
                template_version['id'],
                prompt,
                context_data,
                llm_result
            )
            
            # Step H: Perform QA
            qa_result = self.perform_qa(generation_run_id, llm_result['parsed'])
            
            # Step I: Persist QA run
            qa_run_id = self.persist_qa_run(generation_run_id, qa_result)
            
            # Step J: Persist approved playbook if QA passed
            approved_playbook_id = self.persist_approved_playbook(
                generation_run_id,
                llm_result['parsed'],
                qa_result['result']
            )
            
            # Step K: Update queue status
            final_status = "completed" if qa_result['result'] == "approved" else "failed"
            self.update_queue_status(queue_id, final_status)
            
            # Print summary
            print("\n" + "=" * 50)
            print("RUN 1 COMPLETE")
            print("-" * 50)
            print(f"CVE ID: {self.cve_id}")
            print(f"Queue ID: {queue_id}")
            print(f"Generation Run ID: {generation_run_id}")
            print(f"QA Run ID: {qa_run_id}")
            print(f"QA Result: {qa_result['result']}")
            if approved_playbook_id:
                print(f"Approved Playbook ID: {approved_playbook_id}")
            print(f"Template Version ID: {template_version['id']}")
            print(f"Model Used: {llm_result['model']}")
            print("=" * 50)
            
            return True
            
        except Exception as e:
            print(f"\n[ERROR] Generation failed: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run playbook generation without vector retrieval')
    parser.add_argument('--mode', default='none', help='Retrieval mode (default: none)')
    
    args = parser.parse_args()
    
    generator = PlaybookGenerator(mode=args.mode)
    success = generator.run_generation()
    
    if success:
        print("\nRun 1 execution successful!")
        sys.exit(0)
    else:
        print("\nRun 1 execution failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()