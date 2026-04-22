"""
Test script for v0.2.2 metadata enrichment.
Version: v0.2.2
Timestamp (UTC): 2026-04-18T15:29:46Z
"""

from __future__ import annotations

import sys
import os
import logging

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from scripts.prod.continuous_pipeline_v0_2_1.db_clients import PlaybookEngineClient


def verify_generation_runs_schema():
    """Verify that generation_runs table has all required columns."""
    db = PlaybookEngineClient()
    
    # Check current columns
    columns = db.table_columns('public', 'generation_runs')
    print(f"Current generation_runs columns: {columns}")
    
    # Required columns for v0.2.2
    required_columns = ['model', 'run_duration_seconds', 'creator_script']
    missing = [col for col in required_columns if col not in columns]
    
    if missing:
        print(f"ERROR: Missing required columns: {missing}")
        return False
    
    print(f"SUCCESS: All required columns are present")
    
    # Check recent generation runs for metadata
    print("\nChecking recent generation runs for metadata...")
    try:
        rows = db.fetch_all(
            """
            SELECT id, cve_id, model, run_duration_seconds, creator_script, status, created_at
            FROM public.generation_runs
            ORDER BY id DESC
            LIMIT 10
            """
        )
        
        if rows:
            print(f"Found {len(rows)} recent generation runs")
            for i, row in enumerate(rows):
                print(f"\nRow {i+1}:")
                print(f"  ID: {row.get('id')}")
                print(f"  CVE: {row.get('cve_id')}")
                print(f"  Model: {row.get('model')}")
                print(f"  Duration: {row.get('run_duration_seconds')}")
                print(f"  Creator Script: {row.get('creator_script')}")
                print(f"  Status: {row.get('status')}")
        else:
            print("No generation runs found in database")
            
    except Exception as e:
        print(f"ERROR: Failed to query generation_runs: {e}")
        return False
    
    return True


def test_pipeline_executor_import():
    """Test that PipelineExecutor can be imported with new parameters."""
    try:
        from scripts.prod.continuous_pipeline_v0_2_1.pipeline_executor import PipelineExecutor
        executor = PipelineExecutor()
        print("SUCCESS: PipelineExecutor imported and instantiated")
        
        # Check if run method accepts creator_script parameter
        import inspect
        sig = inspect.signature(executor.run)
        params = list(sig.parameters.keys())
        if 'creator_script' in params:
            print("SUCCESS: executor.run() accepts creator_script parameter")
        else:
            print("ERROR: executor.run() does not accept creator_script parameter")
            return False
            
    except Exception as e:
        print(f"ERROR: Failed to import PipelineExecutor: {e}")
        return False
    
    return True


def test_generation_payload_builder_import():
    """Test that GenerationPayloadBuilder can be imported with new parameters."""
    try:
        from scripts.prod.continuous_pipeline_v0_2_1.generation_payload_builder import GenerationPayloadBuilder
        from scripts.prod.continuous_pipeline_v0_2_1.db_clients import PlaybookEngineClient
        from scripts.prod.continuous_pipeline_v0_2_1.opensearch_client import OpenSearchClient
        
        db = PlaybookEngineClient()
        os_client = OpenSearchClient()
        builder = GenerationPayloadBuilder(db, os_client)
        print("SUCCESS: GenerationPayloadBuilder imported and instantiated")
        
        # Check if persist_generation_run method accepts new parameters
        import inspect
        sig = inspect.signature(builder.persist_generation_run)
        params = list(sig.parameters.keys())
        required_params = ['model', 'run_duration_seconds', 'creator_script']
        missing = [p for p in required_params if p not in params]
        
        if missing:
            print(f"ERROR: persist_generation_run() missing parameters: {missing}")
            return False
        else:
            print("SUCCESS: persist_generation_run() accepts all new parameters")
            
    except Exception as e:
        print(f"ERROR: Failed to import GenerationPayloadBuilder: {e}")
        return False
    
    return True


def main():
    print("=== Testing v0.2.2 Metadata Enrichment ===\n")
    
    tests = [
        ("Database Schema", verify_generation_runs_schema),
        ("PipelineExecutor Import", test_pipeline_executor_import),
        ("GenerationPayloadBuilder Import", test_generation_payload_builder_import),
    ]
    
    all_passed = True
    for test_name, test_func in tests:
        print(f"\n--- Testing {test_name} ---")
        try:
            if test_func():
                print(f"[PASS] {test_name}")
            else:
                print(f"[FAIL] {test_name}")
                all_passed = False
        except Exception as e:
            print(f"[ERROR] {test_name}: {e}")
            all_passed = False
    
    print("\n=== Test Summary ===")
    if all_passed:
        print("[SUCCESS] All tests passed!")
        return 0
    else:
        print("[FAILURE] Some tests failed")
        return 1


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    sys.exit(main())