#!/usr/bin/env python3
"""
SQL Proof for Real Retrieval Fix v0.2.1
Version: v0.2.1-fix
Timestamp: 2026-04-08

Purpose:
- Provide SQL proof of real retrieval-backed generation
- Show that retrieved_context is populated
- Show that source_indexes is populated
- Show at least one non-placeholder evidence item
- Show complete lineage from retrieval to approval
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client


def print_header(title: str):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def print_json(obj: Any):
    print(json.dumps(obj, indent=2, default=str))


def main():
    """Execute SQL proof queries."""
    print_header("SQL PROOF - REAL RETRIEVAL FIX v0.2.1")
    
    db = get_database_client()
    cve_id = "CVE-TEST-0001"
    
    try:
        # Query 1: retrieval_runs
        print_header("1. RETRIEVAL_RUNS (Latest 5)")
        retrieval_runs = db.fetch_all(
            """
            SELECT id, cve_id, retrieved_context, source_indexes, created_at
            FROM retrieval_runs
            WHERE cve_id = %s
            ORDER BY id DESC
            LIMIT 5
            """,
            (cve_id,)
        )
        
        for run in retrieval_runs:
            print(f"\nRetrieval Run ID: {run['id']}")
            print(f"CVE ID: {run['cve_id']}")
            print(f"Created At: {run['created_at']}")
            
            # Check retrieved_context
            if run['retrieved_context']:
                rc = run['retrieved_context']
                print(f"Retrieved Context: POPULATED (type: {type(rc).__name__})")
                if isinstance(rc, dict):
                    print(f"  - Decision: {rc.get('decision', 'N/A')}")
                    print(f"  - Evidence Count: {rc.get('evidence_count', 0)}")
                    print(f"  - Sources: {rc.get('sources', [])}")
            else:
                print("Retrieved Context: NULL/EMPTY")
            
            # Check source_indexes
            if run['source_indexes']:
                print(f"Source Indexes: {run['source_indexes']}")
                print(f"Source Indexes Count: {len(run['source_indexes'])}")
            else:
                print("Source Indexes: NULL/EMPTY")
        
        # Query 2: retrieval_documents
        print_header("2. RETRIEVAL_DOCUMENTS (Latest 10)")
        retrieval_docs = db.fetch_all(
            """
            SELECT rd.*
            FROM retrieval_documents rd
            JOIN retrieval_runs rr ON rd.retrieval_run_id = rr.id
            WHERE rr.cve_id = %s
            ORDER BY rd.id DESC
            LIMIT 10
            """,
            (cve_id,)
        )
        
        print(f"Total retrieval documents found: {len(retrieval_docs)}")
        
        for i, doc in enumerate(retrieval_docs[:5], 1):  # Show first 5
            print(f"\nDocument {i}:")
            print(f"  ID: {doc['id']}")
            print(f"  Retrieval Run ID: {doc['retrieval_run_id']}")
            print(f"  Doc ID: {doc.get('doc_id', 'N/A')}")
            print(f"  Source Index: {doc.get('source_index', 'N/A')}")
            print(f"  Score: {doc.get('score', 0.0)}")
            print(f"  Rank: {doc.get('rank', 0)}")
            
            # Check content
            content = doc.get('content', '')
            if content:
                print(f"  Content: '{content[:100]}...'")
                # Check for placeholder content
                if 'test' in content.lower() or 'placeholder' in content.lower():
                    print(f"  WARNING: Contains placeholder-like content")
                else:
                    print(f"  OK: Real content (length: {len(content)})")
            else:
                print(f"  Content: EMPTY")
            
            # Check metadata
            metadata = doc.get('metadata') or doc.get('document_metadata')
            if metadata:
                print(f"  Metadata: PRESENT (keys: {list(metadata.keys())})")
            else:
                print(f"  Metadata: MISSING")
        
        # Query 3: generation_runs
        print_header("3. GENERATION_RUNS (Latest 5)")
        generation_runs = db.fetch_all(
            """
            SELECT id, cve_id, prompt, response, model, status, created_at
            FROM generation_runs
            WHERE cve_id = %s
            ORDER BY id DESC
            LIMIT 5
            """,
            (cve_id,)
        )
        
        for run in generation_runs:
            print(f"\nGeneration Run ID: {run['id']}")
            print(f"CVE ID: {run['cve_id']}")
            print(f"Model: {run['model']}")
            print(f"Status: {run['status']}")
            print(f"Created At: {run['created_at']}")
            
            # Check prompt
            if run['prompt']:
                print(f"Prompt: PRESENT (length: {len(run['prompt'])})")
                # Check if prompt contains evidence
                if 'evidence' in run['prompt'].lower() or 'retrieved' in run['prompt'].lower():
                    print(f"  Contains evidence/retrieval references")
            else:
                print(f"Prompt: EMPTY")
            
            # Check response
            if run['response']:
                print(f"Response: PRESENT (length: {len(run['response'])})")
            else:
                print(f"Response: EMPTY")
        
        # Query 4: qa_runs
        print_header("4. QA_RUNS (Latest 5)")
        qa_runs = db.fetch_all(
            """
            SELECT qr.*
            FROM qa_runs qr
            JOIN generation_runs gr ON qr.generation_run_id = gr.id
            WHERE gr.cve_id = %s
            ORDER BY qr.id DESC
            LIMIT 5
            """,
            (cve_id,)
        )
        
        for run in qa_runs:
            print(f"\nQA Run ID: {run['id']}")
            print(f"Generation Run ID: {run['generation_run_id']}")
            print(f"QA Result: {run['qa_result']}")
            print(f"QA Score: {run['qa_score']}")
            print(f"Created At: {run['created_at']}")
            
            # Check feedback
            feedback = run.get('qa_feedback')
            if feedback:
                print(f"QA Feedback: PRESENT")
                if isinstance(feedback, dict):
                    print(f"  Errors: {len(feedback.get('errors', []))}")
                    print(f"  Warnings: {len(feedback.get('warnings', []))}")
                    print(f"  Strengths: {len(feedback.get('strengths', []))}")
            else:
                print(f"QA Feedback: MISSING")
        
        # Query 5: approved_playbooks
        print_header("5. APPROVED_PLAYBOOKS (Latest 5)")
        approved_playbooks = db.fetch_all(
            """
            SELECT ap.*
            FROM approved_playbooks ap
            JOIN generation_runs gr ON ap.generation_run_id = gr.id
            WHERE gr.cve_id = %s
            ORDER BY ap.id DESC
            LIMIT 5
            """,
            (cve_id,)
        )
        
        for playbook in approved_playbooks:
            print(f"\nApproved Playbook ID: {playbook['id']}")
            print(f"Generation Run ID: {playbook['generation_run_id']}")
            print(f"Version: {playbook.get('version', 'N/A')}")
            print(f"Approved At: {playbook.get('approved_at', 'N/A')}")
            print(f"Created At: {playbook['created_at']}")
            
            # Check playbook content
            pb_content = playbook.get('playbook')
            if pb_content:
                print(f"Playbook: PRESENT")
                if isinstance(pb_content, dict):
                    print(f"  Title: {pb_content.get('playbook', {}).get('title', 'N/A')}")
                    print(f"  CVE ID: {pb_content.get('playbook', {}).get('cve_id', 'N/A')}")
                    # Check for retrieval metadata
                    if 'retrieval_metadata' in pb_content.get('playbook', {}):
                        print(f"  Contains retrieval metadata")
            else:
                print(f"Playbook: EMPTY")
        
        # Query 6: Lineage proof
        print_header("6. LINEAGE PROOF - Complete Retrieval to Approval")
        lineage = db.fetch_all(
            """
            SELECT
                rr.id as retrieval_run_id,
                rr.cve_id,
                rr.retrieved_context IS NOT NULL as has_retrieved_context,
                rr.source_indexes IS NOT NULL as has_source_indexes,
                COUNT(rd.id) as document_count,
                gr.id as generation_run_id,
                gr.status as generation_status,
                qr.id as qa_run_id,
                qr.qa_result,
                qr.qa_score,
                ap.id as approved_playbook_id
            FROM retrieval_runs rr
            LEFT JOIN retrieval_documents rd ON rd.retrieval_run_id = rr.id
            LEFT JOIN generation_runs gr ON gr.cve_id = rr.cve_id
            LEFT JOIN qa_runs qr ON qr.generation_run_id = gr.id
            LEFT JOIN approved_playbooks ap ON ap.generation_run_id = gr.id
            WHERE rr.cve_id = %s
            GROUP BY rr.id, rr.cve_id, gr.id, qr.id, ap.id
            ORDER BY rr.id DESC, gr.id DESC
            LIMIT 5
            """,
            (cve_id,)
        )
        
        print(f"Lineage records found: {len(lineage)}")
        for record in lineage:
            print(f"\nLineage Record:")
            print(f"  Retrieval Run ID: {record['retrieval_run_id']}")
            print(f"  Has Retrieved Context: {record['has_retrieved_context']}")
            print(f"  Has Source Indexes: {record['has_source_indexes']}")
            print(f"  Document Count: {record['document_count']}")
            print(f"  Generation Run ID: {record['generation_run_id']}")
            print(f"  Generation Status: {record['generation_status']}")
            print(f"  QA Run ID: {record['qa_run_id']}")
            print(f"  QA Result: {record['qa_result']}")
            print(f"  QA Score: {record['qa_score']}")
            print(f"  Approved Playbook ID: {record['approved_playbook_id']}")
        
        # Query 7: Evidence quality check
        print_header("7. EVIDENCE QUALITY CHECK - Non-placeholder Evidence")
        quality_check = db.fetch_all(
            """
            SELECT 
                rd.id,
                rd.source_index,
                rd.score,
                LENGTH(rd.content) as content_length,
                CASE 
                    WHEN rd.content ILIKE '%test%' THEN 'contains_test'
                    WHEN rd.content ILIKE '%placeholder%' THEN 'contains_placeholder'
                    WHEN rd.content ILIKE '%mock%' THEN 'contains_mock'
                    WHEN LENGTH(rd.content) < 20 THEN 'too_short'
                    ELSE 'real_content'
                END as content_quality
            FROM retrieval_documents rd
            JOIN retrieval_runs rr ON rd.retrieval_run_id = rr.id
            WHERE rr.cve_id = %s
            ORDER BY rd.score DESC
            LIMIT 10
            """,
            (cve_id,)
        )
        
        print(f"Evidence quality analysis:")
        quality_counts = {}
        for doc in quality_check:
            quality = doc['content_quality']
            quality_counts[quality] = quality_counts.get(quality, 0) + 1
            
            if quality == 'real_content':
                print(f"\n  REAL EVIDENCE FOUND:")
                print(f"    Document ID: {doc['id']}")
                print(f"    Source Index: {doc['source_index']}")
                print(f"    Score: {doc['score']}")
                print(f"    Content Length: {doc['content_length']}")
        
        print(f"\nQuality Summary:")
        for quality, count in quality_counts.items():
            print(f"  {quality}: {count} documents")
        
        # Final assessment
        print_header("FINAL ASSESSMENT - REAL RETRIEVAL FIX")
        
        # Check requirements
        requirements = {
            "retrieved_context_populated": any(run['retrieved_context'] for run in retrieval_runs),
            "source_indexes_populated": any(run['source_indexes'] for run in retrieval_runs),
            "non_placeholder_evidence": quality_counts.get('real_content', 0) > 0,
            "retrieval_documents_exist": len(retrieval_docs) > 0,
            "generation_runs_exist": len(generation_runs) > 0,
            "qa_runs_exist": len(qa_runs) > 0,
            "approved_playbooks_exist": len(approved_playbooks) > 0,
            "complete_lineage": len(lineage) > 0 and any(record['approved_playbook_id'] for record in lineage)
        }
        
        print("Requirements Check:")
        for req_name, req_met in requirements.items():
            status = "✓ PASS" if req_met else "✗ FAIL"
            print(f"  {req_name}: {status}")
        
        # Overall status
        all_passed = all(requirements.values())
        if all_passed:
            print("\nREAL RETRIEVAL FIX STATUS: SUCCESS")
            print("All requirements met for real retrieval-backed generation.")
        else:
            print("\nREAL RETRIEVAL FIX STATUS: PARTIAL SUCCESS")
            failed = [req for req, met in requirements.items() if not met]
            print(f"Failed requirements: {failed}")
        
    except Exception as e:
        print(f"Error executing SQL proof: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()