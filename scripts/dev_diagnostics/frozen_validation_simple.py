#!/usr/bin/env python3
"""
VS.ai — Playbook Engine Gen-3
Frozen Validation Directive - Simple Implementation
"""

import os
import sys
import json
import time
import re
from pathlib import Path
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client
from src.utils.opensearch_client import get_opensearch_client
from src.utils.llm_client import LLMClient
from src.validation.canonical_validator import validate_playbook_canonical
from src.qa.enforcement_engine import evaluate_playbook


def run_frozen_validation(cve_id="CVE-2023-4863", mode="vector"):
    """Run frozen validation directive."""
    
    print("=" * 80)
    print("VS.ai — PLAYBOOK ENGINE FROZEN VALIDATION")
    print(f"Timestamp (UTC): {datetime.utcnow().isoformat()}")
    print(f"Target CVE: {cve_id}")
    print(f"Mode: {mode} retrieval")
    print("=" * 80)
    
    results = {
        "directive_timestamp": "2026-04-09",
        "cve_id": cve_id,
        "retrieval_mode": mode,
        "start_time": datetime.utcnow().isoformat(),
        "steps": {}
    }
    
    try:
        # Initialize clients
        db = get_database_client()
        opensearch = get_opensearch_client()
        
        # Step 1: Load context snapshot
        print("\n1. Loading context snapshot...")
        snapshot = db.fetch_one(
            "SELECT id, cve_id, context_data FROM cve_context_snapshot WHERE cve_id = %s",
            (cve_id,)
        )
        
        if not snapshot:
            raise ValueError(f"No context snapshot found for {cve_id}")
        
        context_data = snapshot['context_data']
        results["steps"]["context_snapshot"] = {
            "loaded": True,
            "vendor": context_data.get("vendor"),
            "product": context_data.get("product"),
            "description_excerpt": context_data.get("description", "")[:100] + "..." if len(context_data.get("description", "")) > 100 else context_data.get("description", "")
        }
        
        print(f"   [OK] Loaded context for {context_data.get('vendor', 'Unknown')} {context_data.get('product', 'Unknown')}")
        
        # Step 2: Perform OpenSearch/NVD retrieval
        print("\n2. Performing OpenSearch/NVD retrieval...")
        
        # Extract key information for retrieval query
        cve_description = context_data.get("description", "")
        
        query_body = {
            "size": 5,
            "query": {
                "match": {
                    "content": cve_description[:500]
                }
            }
        }
        
        response = opensearch.search(
            index="spring-ai-document-index",
            body=query_body,
            size=5
        )
        
        hits = response.get('hits', {}).get('hits', [])
        retrieved_docs = []
        
        for i, hit in enumerate(hits):
            doc = {
                "source_index": hit.get('_index', 'unknown'),
                "document_id": hit.get('_id', f'doc-{i}'),
                "score": hit.get('_score', 0.0),
                "rank": i + 1,
                "content": hit.get('_source', {}).get('content', ''),
                "metadata": {
                    "title": hit.get('_source', {}).get('title', ''),
                    "source": hit.get('_source', {}).get('source', ''),
                    "timestamp": hit.get('_source', {}).get('timestamp', '')
                }
            }
            retrieved_docs.append(doc)
        
        results["steps"]["retrieval"] = {
            "documents_retrieved": len(retrieved_docs),
            "retrieval_summary": f"Retrieved {len(retrieved_docs)} documents from {mode} search"
        }
        
        print(f"   [OK] Retrieved {len(retrieved_docs)} documents")
        
        # Step 3: Load frozen canonical prompt template
        print("\n3. Loading frozen canonical prompt template...")
        
        template_version = db.fetch_one('''
            SELECT v.id, v.template_id, v.version,
                   v.system_block, v.instruction_block,
                   v.workflow_block, v.output_schema_block,
                   t.name as template_name
            FROM prompt_template_versions v
            JOIN prompt_templates t ON v.template_id = t.id
            WHERE v.is_active = true
            ORDER BY v.created_at DESC
            LIMIT 1
        ''')
        
        if not template_version:
            raise ValueError("No active prompt template version found")
        
        results["steps"]["prompt_template"] = {
            "template_id": template_version['id'],
            "template_name": template_version['template_name'],
            "version": template_version['version'],
            "is_canonical": 'canonical' in template_version.get('system_block', '').lower() or 
                           'Group 6.6' in template_version.get('system_block', '')
        }
        
        print(f"   [OK] Using {template_version['template_name']} v{template_version['version']}")
        
        # Step 4: Render prompt with frozen canonical template
        print("\n4. Rendering prompt with frozen canonical template...")
        
        # Normalize context data for prompt
        normalized_context = {
            "cve_id": context_data.get("cve_id", cve_id),
            "description": context_data.get("description", ""),
            "cvss_score": context_data.get("cvss_score", 0),
            "cwe": context_data.get("cwe", ""),
            "affected_products": context_data.get("affected_products", []),
            "vulnerability_type": context_data.get("vulnerability_type", ""),
            "attack_vector": context_data.get("attack_vector", ""),
            "references": context_data.get("references", []),
            "vendor": context_data.get("vendor", ""),
            "product": context_data.get("product", ""),
            "severity": context_data.get("severity", ""),
            "affected_versions": context_data.get("affected_versions", []),
            "fixed_versions": context_data.get("fixed_versions", []),
            "affected_platforms": context_data.get("affected_platforms", [])
        }
        
        # Prepare retrieved evidence section
        evidence_section = "## Retrieved Evidence from Security Knowledge Base\n\n"
        
        if retrieved_docs:
            for i, doc in enumerate(retrieved_docs, 1):
                evidence_section += f"### Document {i}: {doc['metadata'].get('title', 'Untitled')}\n"
                evidence_section += f"**Source:** {doc['metadata'].get('source', 'Unknown')}\n"
                evidence_section += f"**Relevance Score:** {doc['score']:.3f}\n"
                evidence_section += f"**Content:** {doc['content'][:300]}...\n\n"
        else:
            evidence_section += "No relevant documents retrieved from knowledge base.\n\n"
        
        # Build prompt from template blocks
        prompt_parts = []
        
        if template_version.get('system_block'):
            prompt_parts.append(f"System: {template_version['system_block']}")
        
        if template_version.get('instruction_block'):
            prompt_parts.append(f"Instructions: {template_version['instruction_block']}")
        
        if template_version.get('workflow_block'):
            prompt_parts.append(f"Workflow: {template_version['workflow_block']}")
        
        prompt_parts.append(f"\n## CVE Context Data\n{json.dumps(normalized_context, indent=2)}")
        prompt_parts.append(f"\n{evidence_section}")
        
        if template_version.get('output_schema_block'):
            prompt_parts.append(f"\n## Output Schema\n{template_version['output_schema_block']}")
        
        prompt = "\n\n".join(prompt_parts)
        
        results["steps"]["prompt_rendering"] = {
            "prompt_length": len(prompt),
            "evidence_documents": len(retrieved_docs),
            "exact_prompt_excerpt": prompt[:500] + "..." if len(prompt) > 500 else prompt
        }
        
        print(f"   [OK] Rendered prompt ({len(prompt)} chars) with {len(retrieved_docs)} evidence documents")
        
        # Step 5: Call LLM with frozen canonical prompt
        print("\n5. Calling LLM with frozen canonical prompt...")
        
        llm_client = LLMClient()
        start_time = time.time()
        
        print(f"   Model: {llm_client.model}")
        print(f"   Timeout: {llm_client.timeout_seconds}s")
        
        llm_response = llm_client.generate(prompt)
        elapsed_time = time.time() - start_time
        
        if llm_response.get("status") == "failed":
            error_msg = llm_response.get("error", "Unknown LLM error")
            raise Exception(f"LLM generation failed: {error_msg}")
        
        raw_response = llm_response.get("raw_text", "")
        
        if not raw_response:
            raise Exception("LLM returned empty response")
        
        results["steps"]["llm_generation"] = {
            "model": llm_client.model,
            "elapsed_time": elapsed_time,
            "response_length": len(raw_response),
            "raw_response_excerpt": raw_response[:500] + "..." if len(raw_response) > 500 else raw_response
        }
        
        print(f"   [OK] LLM response received in {elapsed_time:.2f}s ({len(raw_response)} chars)")
        
        # Step 6: Parse output
        print("\n6. Parsing LLM output...")
        
        # Try to extract JSON if response contains markdown
        json_match = re.search(r'```json\s*(.*?)\s*```', raw_response, re.DOTALL)
        if json_match:
            raw_response = json_match.group(1)
        
        json_match = re.search(r'```\s*(.*?)\s*```', raw_response, re.DOTALL)
        if json_match:
            raw_response = json_match.group(1)
        
        parsed_response = json.loads(raw_response)
        
        results["steps"]["parsing"] = {
            "success": True,
            "parsed_keys": list(parsed_response.keys())
        }
        
        print(f"   [OK] Parsed response with keys: {list(parsed_response.keys())}")
        
        # Step 7: Run canonical validation
        print("\n7. Running canonical validation...")
        
        is_valid, errors = validate_playbook_canonical(parsed_response)
        results["steps"]["canonical_validation"] = {
            "passed": is_valid,
            "errors": errors if not is_valid else []
        }
        
        if not is_valid:
            print(f"   [FAIL] Canonical validation failed with {len(errors)} errors:")
            for error in errors:
                print(f"     - {error}")
            results["final_result"] = "FAILED - Canonical validation"
            return results
        
        print(f"   [OK] Canonical validation passed")
        
        # Step 8: Run QA
        print("\n8. Running QA enforcement...")
        
        qa_result = evaluate_playbook(
            playbook=parsed_response,
            expected_cve_id=cve_id
        )
        
        results["steps"]["qa_enforcement"] = {
            "status": qa_result.get("status"),
            "score": qa_result.get("score"),
            "decision": qa_result.get("decision"),
            "feedback": qa_result.get("feedback", {})
        }
        
        if qa_result.get("status") != "PASS":
            print(f"   [FAIL] QA failed with score {qa_result.get('score', 0):.2f}")
            results["final_result"] = f"FAILED - QA (score: {qa_result.get('score', 0):.2f})"
            return results
        
        print(f"   [OK] QA passed with score {qa_result.get('score', 0):.2f}")
        
        # Success!
        results["final_result"] = "SUCCESS - New canonical playbook generated and validated"
        results["end_time"] = datetime.utcnow().isoformat()
        
        print("\n" + "=" * 80)
        print("FROZEN VALIDATION COMPLETE - SUCCESS")
        print("=" * 80)
        print(f"CVE: {cve_id}")
        print(f"Retrieval: {results['steps']['retrieval']['retrieval_summary']}")
        print(f"Prompt: Frozen canonical template v{template_version['version']}")
        print(f"Model: {llm_client.model}")
        print(f"Canonical Validation: PASSED")
        print(f"QA: PASSED (score: {qa_result.get('score', 0):.2f})")
        print(f"Result: New canonical playbook generated successfully")
        print("=" * 80)
        
        return results
        
    except Exception as e:
        print(f"\n[ERROR] Frozen validation failed: {e}")
        import traceback
        traceback.print_exc()
        results["final_result"] = f"FAILED - Exception: {str(e)}"
        results["end_time"] = datetime.utcnow().isoformat()
        return results


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run frozen validation with canonical prompt')
    parser.add_argument('--cve', default='CVE-2023-4863',
                       help='CVE ID to process (default: CVE-2023-4863)')
    parser.add_argument('--mode', choices=['vector', 'hybrid'], default='vector',
                       help='Retrieval mode: vector or hybrid (default: vector)')
    
    args = parser.parse_args()
    
    print("\n" + "=" * 80)
    print("VS.ai — Playbook Engine Gen-3")
    print("FROZEN VALIDATION DIRECTIVE")
    print("Timestamp (UTC): 2026-04-09")
    print("=" * 80)
    print("OBJECTIVE: Single frozen-prompt playbook validation starting from OpenSearch/NVD")
    print(f"TARGET: {args.cve}")
    print(f"MODE: {args.mode} retrieval")
    print("RULES: No code changes to existing code, use frozen canonical prompt, real LLM call")
    print("=" * 80)
    
    # Run validation
    results = run_frozen_validation(args.cve, args.mode)
    
    # Save results to file
    import os
    os.makedirs("logs/frozen_validation", exist_ok=True)
    output_file = f"logs/frozen_validation/frozen_validation_{args.cve}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nValidation results saved to: {output_file}")
    
    # Exit with appropriate code
    if results.get("final_result", "").startswith("SUCCESS"):
        print("\n✓ FROZEN VALIDATION DIRECTIVE COMPLETED SUCCESSFULLY")
        sys.exit(0)
    else:
        print(f"\n✗ FROZEN VALIDATION DIRECTIVE FAILED: {results.get('final_result', 'Unknown error')}")
        sys.exit(1)


if __name__ == "__main__":
    main()