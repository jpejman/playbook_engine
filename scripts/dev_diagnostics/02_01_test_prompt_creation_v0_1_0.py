#!/usr/bin/env python3
"""
Test prompt creation only (no LLM calls)
Version: v0.1.0
Timestamp: 2026-04-08

Purpose:
Test the full pre-LLM pipeline:
1. collect context
2. retrieve evidence
3. deduplicate/filter
4. decide retrieval quality
5. build prompt input package
6. render prompt
7. validate prompt
8. stop (no LLM call)
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client, assert_expected_database
from src.retrieval.evidence_collector import collect_evidence
from src.retrieval.prompt_input_builder import build_prompt_inputs, PromptInputBuilder

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def print_header(title: str):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)

def print_section(title: str):
    print(f"\n--- {title} ---")

def main():
    """Execute prompt-only test."""
    print_header("PROMPT-ONLY TEST v0.1.0 - NO LLM CALLS")
    
    cve_id = "CVE-TEST-0001"
    results = {}
    
    try:
        # Step 1: Assert database target
        print_section("1. Database Target")
        db = get_database_client()
        assert_expected_database('playbook_engine')
        current_db = db.fetch_one("SELECT current_database()")
        print(f"Connected to: {current_db['current_database']}")
        results['database'] = current_db['current_database']
        
        # Step 2: Load context snapshot
        print_section("2. Load Context Snapshot")
        context_snapshot = db.fetch_one(
            "SELECT id, cve_id, context_data FROM cve_context_snapshot WHERE cve_id = %s",
            (cve_id,)
        )
        
        if not context_snapshot:
            raise ValueError(f"No context snapshot found for {cve_id}")
        
        context_data = context_snapshot['context_data']
        print(f"Context snapshot ID: {context_snapshot['id']}")
        print(f"CVE ID: {context_data.get('cve_id', cve_id)}")
        print(f"Description length: {len(context_data.get('description', ''))}")
        results['context_snapshot_id'] = context_snapshot['id']
        
        # Step 3: Load active prompt template
        print_section("3. Load Active Prompt Template")
        template_version = db.fetch_one(
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
        
        print(f"Template: {template_version['template_name']} v{template_version['version']}")
        print(f"Template version ID: {template_version['id']}")
        results['template_version_id'] = template_version['id']
        results['template_name'] = template_version['template_name']
        
        # Step 4: Collect evidence
        print_section("4. Collect Evidence")
        evidence_collector = collect_evidence(cve_id, context_data)
        aggregated_package = evidence_collector.collect_all_evidence()
        
        print(f"Evidence count before dedup/filter: {aggregated_package.get('evidence_count', 0)}")
        print(f"Retrieval decision: {aggregated_package.get('decision', 'unknown')}")
        print(f"Sources: {aggregated_package.get('sources', [])}")
        print(f"OpenSearch count: {aggregated_package.get('opensearch_count', 0)}")
        print(f"Vulnstrike count: {aggregated_package.get('vulnstrike_count', 0)}")
        
        results['evidence_count_before'] = aggregated_package.get('evidence_count', 0)
        results['retrieval_decision'] = aggregated_package.get('decision', 'unknown')
        results['sources'] = aggregated_package.get('sources', [])
        
        # Step 5: Build prompt input package
        print_section("5. Build Prompt Input Package")
        input_package = build_prompt_inputs(
            cve_id,
            context_data,
            evidence_collector,
            template_version
        )
        
        print(f"Input package keys: {list(input_package.keys())}")
        print(f"Evidence count in package: {len(input_package.get('retrieved_evidence', []))}")
        print(f"Source indexes: {input_package.get('source_indexes', [])}")
        print(f"Retrieval quality: {input_package.get('retrieval_quality', {})}")
        
        results['evidence_count_after'] = len(input_package.get('retrieved_evidence', []))
        results['source_indexes'] = input_package.get('source_indexes', [])
        
        # Step 6: Render prompt
        print_section("6. Render Prompt")
        builder = PromptInputBuilder(
            cve_id,
            context_data,
            evidence_collector,
            template_version
        )
        
        rendered_prompt = builder.render_prompt(input_package)
        
        print(f"Prompt length: {len(rendered_prompt)} characters")
        print(f"Prompt preview (first 500 chars):")
        print("-" * 50)
        print(rendered_prompt[:500] + "..." if len(rendered_prompt) > 500 else rendered_prompt)
        print("-" * 50)
        
        results['prompt_length'] = len(rendered_prompt)
        
        # Step 7: Validate prompt
        print_section("7. Validate Prompt")
        validation = builder.validate_prompt(rendered_prompt, input_package)
        
        print(f"Prompt valid: {validation['is_valid']}")
        print(f"Prompt length: {validation['prompt_length']}")
        print(f"Evidence count: {validation['evidence_count']}")
        
        if validation['errors']:
            print(f"Errors: {validation['errors']}")
        if validation['warnings']:
            print(f"Warnings: {validation['warnings']}")
        
        print("\nRequirements met:")
        for req, met in validation['requirements_met'].items():
            status = "[PASS]" if met else "[FAIL]"
            print(f"  {status} {req}")
        
        results['prompt_validation'] = validation
        results['prompt_is_valid'] = validation['is_valid']
        
        # Step 8: Print summary
        print_section("8. Test Summary")
        
        summary = {
            "database": results['database'],
            "cve_id": cve_id,
            "context_snapshot_id": results['context_snapshot_id'],
            "template": f"{results['template_name']} (v{template_version['version']})",
            "evidence_stats": {
                "before_dedup_filter": results['evidence_count_before'],
                "after_dedup_filter": results['evidence_count_after'],
                "reduction_percent": round((1 - results['evidence_count_after'] / max(results['evidence_count_before'], 1)) * 100, 1)
            },
            "retrieval_decision": results['retrieval_decision'],
            "source_indexes": results['source_indexes'],
            "prompt_length": results['prompt_length'],
            "prompt_valid": results['prompt_is_valid'],
            "validation_errors": len(validation['errors']),
            "validation_warnings": len(validation['warnings'])
        }
        
        print(json.dumps(summary, indent=2))
        
        # Step 9: Final status
        print_header("TEST COMPLETE - NO LLM CALLS MADE")
        
        if validation['is_valid']:
            print("[PASS] Prompt creation pipeline works end-to-end")
            print("[PASS] Prompt validation passed")
            print("[PASS] Ready for LLM integration")
            
            # Check if we meet the duplicate ratio target
            duplicate_ratio = 1 - (results['evidence_count_after'] / max(results['evidence_count_before'], 1))
            print(f"Duplicate ratio reduction: {duplicate_ratio:.2f}")
            
            if duplicate_ratio > 0.3:
                print(f"[PASS] Duplicate ratio improved significantly")
            else:
                print(f"[WARN] Duplicate ratio improvement limited")
            
            # Check source filtering
            low_value_sources = ['vulnstrike.cve_queue', 'vulnstrike.retrieval_runs', 
                                'vulnstrike.generation_runs', 'vulnstrike.approved_playbooks']
            filtered_sources = [s for s in results['source_indexes'] if any(lvs in s for lvs in low_value_sources)]
            if filtered_sources:
                print(f"[WARN] Some low-value sources still present: {filtered_sources}")
            else:
                print("[PASS] Low-value sources filtered out")
            
            print("\nPRE-LLM FIX STATUS: SUCCESS")
        else:
            print("[FAIL] Prompt validation failed")
            print(f"Errors: {validation['errors']}")
            print("\nPRE-LLM FIX STATUS: FAILURE")
        
        # Close evidence collector
        evidence_collector.close()
        
    except Exception as e:
        print(f"Error during prompt-only test: {e}")
        import traceback
        traceback.print_exc()
        print("\nPRE-LLM FIX STATUS: FAILURE")
        sys.exit(1)

if __name__ == "__main__":
    main()