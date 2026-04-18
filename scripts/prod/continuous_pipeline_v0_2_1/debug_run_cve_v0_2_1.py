"""
Debug single CVE runner for continuous_pipeline_v0_2_1
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import traceback
from typing import Any

from .db_clients import PlaybookEngineClient
from .generation_guard import GenerationRunGuard
from .llm_client import LLMClient
from .opensearch_client import OpenSearchClient
from .pipeline_executor import PipelineExecutor
from .production_guard import ProductionPlaybookGuard
from .generation_payload_builder import GenerationPayloadBuilder


class DebugCVERunnerV021:
    def __init__(self):
        self.playbook_engine = PlaybookEngineClient()
        self.opensearch = OpenSearchClient()
        self.llm = LLMClient()
        self.generation_guard = GenerationRunGuard()
        self.production_guard = ProductionPlaybookGuard()
        self.executor = PipelineExecutor()
        self.generation_payload_builder = GenerationPayloadBuilder(self.playbook_engine, self.opensearch)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def run(self, cve_id: str) -> bool:
        print(f"=== Debug Run for CVE: {cve_id} ===\n")
        
        success = True
        
        # Step 1: Check production existence
        print("1. Checking production existence...")
        try:
            prod_exists = self.production_guard.exists(cve_id)
            print(f"   Production exists: {prod_exists}")
            if prod_exists:
                print("   [WARNING] CVE already in production, skipping further processing")
                return True
        except Exception as e:
            print(f"   ✗ Failed to check production: {e}")
            success = False
        
        # Step 2: Check generation existence
        print("\n2. Checking generation existence...")
        try:
            gen_exists = self.generation_guard.exists_completed_nonempty(cve_id)
            print(f"   Generation exists: {gen_exists}")
            if gen_exists:
                print("   [WARNING] CVE already generated, skipping further processing")
                return True
        except Exception as e:
            print(f"   ✗ Failed to check generation: {e}")
            success = False
        
        # Step 3: Check OpenSearch for CVE
        print("\n3. Fetching from OpenSearch...")
        try:
            cve_doc = self.opensearch.fetch_cve(cve_id)
            print(f"   [OK] Found CVE document")
            print(f"   Source fields: {list(cve_doc.keys())}")
            print(f"   Description: {cve_doc.get('description', '')[:100]}...")
        except Exception as e:
            print(f"   [ERROR] Failed to fetch from OpenSearch: {e}")
            success = False
            return False
        
        # Step 4: Test canonical prompt builder
        print("\n4. Testing canonical prompt builder...")
        try:
            # Build generation payload to test canonical components
            generation_payload = self.generation_payload_builder.build_generation_payload(cve_id)
            prompt = generation_payload['prompt']
            debug_info = generation_payload['debug_info']
            
            print(f"   [OK] Canonical prompt built")
            print(f"   Prompt builder: {debug_info.get('prompt_builder_selected')}")
            print(f"   Schema module: {debug_info.get('schema_module_selected')}")
            print(f"   Prompt length: {debug_info.get('prompt_length')} chars")
            print(f"   Evidence count: {debug_info.get('evidence_count')}")
            print(f"   Retrieval decision: {debug_info.get('retrieval_decision')}")
            print(f"   First 200 chars: {prompt[:200]}...")
        except Exception as e:
            print(f"   [ERROR] Failed to build canonical prompt: {e}")
            success = False
        
        # Step 5: Check LLM connection
        print("\n5. Testing LLM connection...")
        try:
            # Simple test query
            test_prompt = "Respond with 'OK' if you can hear me."
            response = self.llm.generate(test_prompt)
            print(f"   [OK] LLM connection successful")
            print(f"   Response: {response.get('response', 'No response')[:100]}...")
        except Exception as e:
            print(f"   [ERROR] LLM connection failed: {e}")
            success = False
        
        # Step 6: Check database tables
        print("\n6. Checking database tables...")
        tables_to_check = [
            ('public', 'cve_context_snapshot'),
            ('public', 'generation_runs'),
            ('public', 'retrieval_runs'),
            ('public', 'retrieval_documents'),
        ]
        
        for schema, table in tables_to_check:
            try:
                columns = self.playbook_engine.table_columns(schema, table)
                print(f"   [OK] {schema}.{table}: {len(columns)} columns")
                if table == 'generation_runs':
                    print(f"      Key columns: {[c for c in columns if c in ['id', 'cve_id', 'status', 'prompt', 'response', 'created_at']]}")
            except Exception as e:
                print(f"   [ERROR] {schema}.{table}: Failed - {e}")
                success = False
        
        # Step 7: Run full pipeline
        print("\n7. Running full pipeline...")
        try:
            results = self.executor.run(cve_id)
            print(f"   [OK] Pipeline execution completed")
            print(f"   Execution status: {results.get('execution_status')}")
            print(f"   Pipeline status: {results.get('pipeline_status')}")
            print(f"   Generation run ID: {results.get('generation_run_id')}")
            print(f"   Context snapshot ID: {results.get('context_snapshot_id')}")
            print(f"   Retrieval run ID: {results.get('retrieval_run_id')}")
            
            if results.get('pipeline_status') == 'success':
                print(f"   [SUCCESS] CVE {cve_id} processed successfully")
                return True
            else:
                print(f"   [FAILED] {results.get('error', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"   [ERROR] Pipeline execution failed: {e}")
            print(f"   Traceback: {traceback.format_exc()}")
            return False
        
        return success

    def verify_db_writes(self, cve_id: str, generation_run_id: int = None) -> bool:
        """Verify that database writes were successful."""
        print(f"\n=== Verifying DB Writes for CVE: {cve_id} ===\n")
        
        success = True
        
        # Check queue table
        print("1. Checking cve_queue...")
        try:
            row = self.playbook_engine.fetch_one(
                "SELECT status, retry_count, failure_type FROM public.cve_queue WHERE cve_id = %s ORDER BY created_at DESC LIMIT 1",
                (cve_id,)
            )
            if row:
                print(f"   [OK] Found queue entry: status={row.get('status')}, retry_count={row.get('retry_count')}, failure_type={row.get('failure_type')}")
            else:
                print(f"   [WARNING] No queue entry found (may be running in debug mode)")
        except Exception as e:
            print(f"   [ERROR] Failed to check queue: {e}")
            success = False
        
        # Check context snapshot
        print("\n2. Checking cve_context_snapshot...")
        try:
            row = self.playbook_engine.fetch_one(
                "SELECT id, created_at FROM public.cve_context_snapshot WHERE cve_id = %s ORDER BY created_at DESC LIMIT 1",
                (cve_id,)
            )
            if row:
                print(f"   [OK] Found context snapshot: id={row.get('id')}, created_at={row.get('created_at')}")
            else:
                print(f"   [WARNING] No context snapshot found")
        except Exception as e:
            print(f"   [ERROR] Failed to check context snapshot: {e}")
            success = False
        
        # Check generation runs
        print("\n3. Checking generation_runs...")
        try:
            query = "SELECT id, status, created_at, response FROM public.generation_runs WHERE cve_id = %s ORDER BY created_at DESC LIMIT 1"
            if generation_run_id:
                query = "SELECT id, status, created_at, response FROM public.generation_runs WHERE id = %s"
                row = self.playbook_engine.fetch_one(query, (generation_run_id,))
            else:
                row = self.playbook_engine.fetch_one(query, (cve_id,))
            
            if row:
                print(f"   [OK] Found generation run: id={row.get('id')}, status={row.get('status')}, created_at={row.get('created_at')}")
                if row.get('response'):
                    print(f"      response length: {len(row.get('response', ''))} chars")
            else:
                print(f"   [WARNING] No generation run found")
        except Exception as e:
            print(f"   [ERROR] Failed to check generation runs: {e}")
            success = False
        
        # Check retrieval runs
        print("\n4. Checking retrieval_runs...")
        try:
            row = self.playbook_engine.fetch_one(
                "SELECT id, created_at FROM public.retrieval_runs WHERE cve_id = %s ORDER BY created_at DESC LIMIT 1",
                (cve_id,)
            )
            if row:
                print(f"   [OK] Found retrieval run: id={row.get('id')}, created_at={row.get('created_at')}")
            else:
                print(f"   [WARNING] No retrieval run found")
        except Exception as e:
            print(f"   [ERROR] Failed to check retrieval runs: {e}")
            success = False
        
        return success


def main():
    parser = argparse.ArgumentParser(description='Debug single CVE runner v0.2.1')
    parser.add_argument('--cve-id', required=True, help='CVE ID to process (e.g., CVE-2025-63458)')
    parser.add_argument('--verify-only', action='store_true', help='Only verify DB writes without processing')
    parser.add_argument('--generation-run-id', type=int, help='Specific generation run ID to verify')
    
    args = parser.parse_args()
    
    runner = DebugCVERunnerV021()
    
    if args.verify_only:
        success = runner.verify_db_writes(args.cve_id, args.generation_run_id)
    else:
        success = runner.run(args.cve_id)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()