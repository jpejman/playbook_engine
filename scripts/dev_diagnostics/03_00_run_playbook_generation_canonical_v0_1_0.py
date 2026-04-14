#!/usr/bin/env python3
"""
Playbook Engine Run with Canonical Validation
Version: v0.1.0
Timestamp: 2026-04-09

Run generation with:
- DB input
- Vector retrieval from OpenSearch
- Prompt construction with retrieved evidence
- LLM call (mock for now)
- Canonical schema validation
- Storage guard enforcement
- DB persistence only if valid
- QA and approval
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client, assert_expected_database
from src.utils.opensearch_client import get_opensearch_client
from src.validation.storage_guard import create_storage_guard
from src.validation.canonical_validator import validate_playbook_canonical, detect_mock_playbook
import psycopg2.extras
from psycopg2.extras import Json


class CanonicalPlaybookGenerator:
    """Playbook generation with canonical validation."""
    
    def __init__(self, cve_id: str = "CVE-2025-54371", mode: str = "vector", production_mode: bool = True):
        self.db = get_database_client()
        self.opensearch = get_opensearch_client()
        self.cve_id = cve_id
        self.mode = mode  # "vector" or "hybrid"
        self.production_mode = production_mode
        self.storage_guard = create_storage_guard(production_mode)
        self.results = {}
        
    def assert_database_target(self):
        """Assert connected to correct database."""
        print("Verifying database target...")
        assert_expected_database('playbook_engine')
        print("  Connected to playbook_engine")
    
    def load_queue_item(self) -> Optional[Dict]:
        """Load pending queue item for CVE."""
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
    
    def perform_vector_retrieval(self, context_data: Dict) -> Dict:
        """
        Perform vector retrieval from OpenSearch.
        """
        print(f"\nPerforming {self.mode} retrieval...")
        
        # Extract key information for retrieval query
        cve_description = context_data.get("description", "")
        vulnerability_type = context_data.get("vulnerability_type", "")
        affected_products = context_data.get("affected_products", [])
        
        # Construct query based on mode
        if self.mode == "vector":
            query_body = {
                "size": 5,
                "query": {
                    "match": {
                        "content": cve_description[:500]
                    }
                }
            }
            vector_metadata = {
                "embedding_dimensions": 768,
                "field": "embedding",
                "note": "Vector search would use knn query in production"
            }
            keyword_query = None
            
        elif self.mode == "hybrid":
            query_body = {
                "size": 5,
                "query": {
                    "bool": {
                        "should": [
                            {
                                "match": {
                                    "content": {
                                        "query": cve_description[:500],
                                        "boost": 1.0
                                    }
                                }
                            },
                            {
                                "multi_match": {
                                    "query": cve_description[:500],
                                    "fields": ["title^2", "content"],
                                    "boost": 0.7
                                }
                            }
                        ]
                    }
                }
            }
            vector_metadata = {
                "embedding_dimensions": 768,
                "note": "Hybrid search would combine vector and keyword in production"
            }
            keyword_query = cve_description[:500]
        
        else:
            raise ValueError(f"Invalid mode: {self.mode}")
        
        print(f"  Mode: {self.mode}")
        print(f"  Querying vector index: spring-ai-document-index")
        
        try:
            # Execute search against vector index
            response = self.opensearch.search(
                index="spring-ai-document-index",
                body=query_body,
                size=5
            )
            
            hits = response.get('hits', {}).get('hits', [])
            print(f"  Retrieved {len(hits)} documents")
            
            # Process retrieved documents
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
                print(f"    Doc {i+1}: {doc['metadata']['title'][:50]}... (score: {doc['score']:.3f})")
            
            retrieval_result = {
                "mode": self.mode,
                "query_body": query_body,
                "documents": retrieved_docs,
                "total_hits": response.get('hits', {}).get('total', {}).get('value', 0),
                "vector_metadata": vector_metadata,
                "keyword_query": keyword_query
            }
            
            self.results['retrieval_result'] = retrieval_result
            return retrieval_result
            
        except Exception as e:
            print(f"  [WARNING] Vector retrieval failed: {e}")
            print("  Using mock retrieval for demonstration")
            
            # Fallback to mock retrieval for demonstration
            return self._mock_vector_retrieval(context_data)
    
    def _mock_vector_retrieval(self, context_data: Dict) -> Dict:
        """Mock vector retrieval for demonstration when OpenSearch is unavailable."""
        cve_description = context_data.get("description", "")
        
        mock_docs = [
            {
                "source_index": "spring-ai-document-index",
                "document_id": "doc-vector-001",
                "score": 0.95,
                "rank": 1,
                "content": f"Security advisory for similar vulnerability: {cve_description[:100]}...",
                "metadata": {
                    "title": "Security Advisory: Similar CVE Pattern",
                    "source": "NVD Database",
                    "timestamp": "2024-01-15T10:30:00Z"
                }
            },
            {
                "source_index": "spring-ai-document-index",
                "document_id": "doc-vector-002",
                "score": 0.87,
                "rank": 2,
                "content": "Remediation steps for web application vulnerabilities including patch management and configuration hardening.",
                "metadata": {
                    "title": "Web App Vulnerability Remediation Guide",
                    "source": "Security Best Practices",
                    "timestamp": "2024-02-20T14:45:00Z"
                }
            }
        ]
        
        return {
            "mode": self.mode,
            "query_body": {"mock": True},
            "documents": mock_docs,
            "total_hits": len(mock_docs),
            "vector_metadata": {"mock": True, "embedding_dimensions": 768},
            "keyword_query": cve_description[:500] if self.mode == "hybrid" else None
        }
    
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
        
        # Validate template is canonical
        system_block = template_version.get('system_block', '')
        if 'canonical' not in system_block.lower() and 'Group 6.6' not in system_block:
            print(f"  [WARNING] Active template may not be canonical")
        
        self.results['template_version_id'] = template_version['id']
        self.results['template_id'] = template_version['template_id']
        
        return template_version
    
    def render_prompt(self, template_version: Dict, context_data: Dict, retrieval_result: Dict) -> str:
        """
        Render prompt from template blocks, context, and retrieved evidence.
        """
        print("\nRendering prompt with retrieved evidence...")
        
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
        
        # Prepare retrieved evidence section
        retrieved_docs = retrieval_result.get('documents', [])
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
        
        rendered_prompt = "\n\n".join(prompt_parts)
        
        print(f"  [OK] Prompt rendered with {len(retrieved_docs)} evidence documents ({len(rendered_prompt)} chars)")
        
        # Store both context and evidence in prompt_inputs
        prompt_inputs = {
            "context": normalized_context,
            "retrieval_mode": retrieval_result['mode'],
            "retrieved_documents_count": len(retrieved_docs),
            "evidence_documents": [
                {
                    "title": doc['metadata'].get('title', ''),
                    "source": doc['metadata'].get('source', ''),
                    "score": doc['score'],
                    "content_snippet": doc['content'][:200]
                }
                for doc in retrieved_docs
            ]
        }
        
        self.results['rendered_prompt'] = rendered_prompt
        self.results['prompt_inputs'] = prompt_inputs
        
        return rendered_prompt
    
    def call_llm_mock_canonical(self, prompt: str) -> Dict[str, Any]:
        """Mock LLM call that generates canonical output."""
        print("\nCalling LLM (mock canonical implementation)...")
        
        # Print LLM configuration being used
        llm_base_url = os.getenv('LLM_BASE_URL', 'https://api.openai.com/v1')
        llm_model = os.getenv('LLM_MODEL', 'gpt-4')
        llm_timeout = os.getenv('REQUEST_TIMEOUT', '30')
        
        print(f"  LLM Configuration:")
        print(f"    Base URL: {llm_base_url}")
        print(f"    Model: {llm_model}")
        print(f"    Timeout: {llm_timeout}s")
        print(f"  Note: Using mock canonical implementation for {self.mode} retrieval")
        
        # Simulate API call delay
        time.sleep(0.5)
        
        # Generate canonical mock response
        canonical_response = {
            "title": f"Canonical Remediation Playbook for {self.cve_id}",
            "cve_id": self.cve_id,
            "vendor": "Test Vendor",
            "product": "Test Product",
            "severity": "High",
            "vulnerability_type": "Buffer Overflow",
            "description": "Test vulnerability description for demonstration.",
            "affected_versions": ["1.0.0", "1.1.0"],
            "fixed_versions": ["1.2.0"],
            "affected_platforms": ["Linux", "Windows"],
            "references": [f"https://example.com/{self.cve_id.lower()}"],
            "retrieval_metadata": {
                "decision": "strong",
                "evidence_count": 2,
                "source_indexes": ["spring-ai-document-index"],
                "generation_timestamp": datetime.utcnow().isoformat()
            },
            "pre_remediation_checks": {
                "required_checks": [
                    {
                        "check_id": "check_1",
                        "description": "Verify system backup exists",
                        "commands": ["ls -la /backup/"],
                        "expected_result": "Backup directory exists with recent files"
                    }
                ],
                "backup_steps": [
                    {
                        "step_id": "backup_1",
                        "description": "Create system backup",
                        "commands": ["tar -czf /backup/system-backup-$(date +%Y%m%d).tar.gz /etc /var"],
                        "verification": "Check backup file size and timestamp"
                    }
                ],
                "prerequisites": ["root access", "backup storage available"]
            },
            "workflows": [
                {
                    "workflow_id": "workflow_1",
                    "workflow_name": "Repository Update Workflow",
                    "workflow_type": "repository_update",
                    "applicability_conditions": {
                        "os_family": ["Linux"],
                        "package_managers": ["apt", "yum"],
                        "environments": ["production", "staging"]
                    },
                    "prerequisites": ["package manager access", "internet connectivity"],
                    "steps": [
                        {
                            "step_number": 1,
                            "title": "Update package repositories",
                            "description": "Refresh package repository metadata to get latest versions",
                            "commands": ["apt-get update", "yum check-update"],
                            "target_os_or_platform": "Linux/Ubuntu",
                            "expected_result": "Package lists updated successfully",
                            "verification": "Check for no error messages in output",
                            "rollback_hint": "No rollback needed for repository update",
                            "evidence_based": True
                        },
                        {
                            "step_number": 2,
                            "title": "Install security update",
                            "description": "Install the security patch for the vulnerable package",
                            "commands": ["apt-get install --only-upgrade test-package", "yum update test-package --security"],
                            "target_os_or_platform": "Linux/Ubuntu",
                            "expected_result": "Package updated to secure version",
                        "verification": f"Verify package version with test command",
                        "rollback_hint": "Downgrade package if needed",
                        "evidence_based": True
                        }
                    ]
                }
            ],
            "post_remediation_validation": {
                "validation_steps": [
                    {
                        "step_id": "validation_1",
                        "description": "Verify vulnerability is patched",
                        "commands": ["vulnerability-scanner --check-cve CVE-TEST"],
                        "expected_outcomes": ["No vulnerabilities found", "CVE status: PATCHED"]
                    }
                ],
                "testing_procedures": [
                    {
                        "test_id": "test_1",
                        "description": "Test system functionality after patch",
                        "commands": ["system-test-suite --run-all"],
                        "pass_criteria": "All tests pass without regression"
                    }
                ]
            },
            "additional_recommendations": [
                {
                    "recommendation_id": "rec_1",
                    "category": "security_hardening",
                    "description": "Implement additional security monitoring",
                    "priority": "medium",
                    "implementation_guidance": "Set up log monitoring for security events"
                }
            ]
        }
        
        raw_response = json.dumps(canonical_response, indent=2)
        
        print(f"  [OK] Generated canonical mock response ({len(raw_response)} chars)")
        self.results['raw_response'] = raw_response
        self.results['parsed_response'] = canonical_response
        
        return {
            "raw": raw_response,
            "parsed": canonical_response,
            "model": llm_model
        }
    
    def persist_generation_run_with_guard(self, queue_id: Optional[int], template_version_id: int, 
                                        prompt: str, prompt_inputs: Dict, llm_result: Dict) -> Optional[int]:
        """Persist generation run with storage guard validation."""
        print("\nPersisting generation run with storage guard...")
        
        # Apply storage guard validation
        should_store, rejected_id, validation_result = self.storage_guard.enforce_storage_guard(
            cve_id=self.cve_id,
            prompt=prompt,
            model=llm_result['model'],
            response=llm_result['parsed'],
            template_version_id=template_version_id,
            db_client=self.db
        )
        
        if not should_store:
            if rejected_id:
                print(f"  [REJECTED] Created rejected generation run ID: {rejected_id}")
                self.results['generation_run_id'] = rejected_id
                self.results['generation_status'] = 'rejected'
                self.results['validation_errors'] = validation_result['errors']
                return rejected_id
            else:
                print(f"  [REJECTED] Generation run rejected (not stored)")
                self.results['generation_status'] = 'rejected'
                self.results['validation_errors'] = validation_result['errors']
                return None
        
        # Validation passed - proceed with storage
        print(f"  [VALIDATION PASSED] Storing generation run...")
        
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
                            Json(prompt_inputs),
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
            self.results['generation_status'] = 'completed'
            return generation_run_id
        else:
            raise ValueError("Failed to get generation run ID from database")
    
    def perform_qa(self, generation_run_id: int, parsed_response: Dict) -> Dict:
        """Perform QA on generated playbook."""
        print("\nPerforming QA...")
        
        # Enhanced QA rules for canonical playbooks
        qa_result = "needs_revision"
        qa_score = 0.0
        qa_feedback = {"errors": [], "warnings": [], "strengths": []}
        
        # Rule 1: Response exists
        if not parsed_response:
            qa_feedback["errors"].append("No parsed response")
        
        # Rule 2: Check canonical structure
        elif "workflows" not in parsed_response:
            qa_feedback["errors"].append("Missing 'workflows' key (non-canonical structure)")
        
        # Rule 3: Contains workflows array
        elif not isinstance(parsed_response.get("workflows"), list):
            qa_feedback["errors"].append("'workflows' must be an array")
        
        elif len(parsed_response["workflows"]) == 0:
            qa_feedback["errors"].append("'workflows' array is empty")
        
        else:
            # Check workflow structure
            workflows = parsed_response["workflows"]
            valid_workflows = 0
            
            for i, workflow in enumerate(workflows):
                if not isinstance(workflow, dict):
                    qa_feedback["errors"].append(f"Workflow {i} is not a dictionary")
                    continue
                
                # Check required workflow fields
                workflow_required = ["workflow_id", "workflow_name", "workflow_type", "steps"]
                missing_fields = [f for f in workflow_required if f not in workflow]
                
                if missing_fields:
                    qa_feedback["errors"].append(f"Workflow {i} missing fields: {missing_fields}")
                else:
                    valid_workflows += 1
                    
                    # Check steps
                    steps = workflow.get("steps", [])
                    if not isinstance(steps, list):
                        qa_feedback["errors"].append(f"Workflow {i} 'steps' must be an array")
                    elif len(steps) == 0:
                        qa_feedback["errors"].append(f"Workflow {i} 'steps' array is empty")
                    else:
                        qa_feedback["strengths"].append(f"Workflow {i} has {len(steps)} steps")
            
            if valid_workflows > 0:
                qa_result = "approved"
                qa_score = 0.85 + (valid_workflows * 0.05)  # Base score + bonus for workflows
                qa_feedback["note"] = f"Canonical validation passed with {valid_workflows} workflows"
            else:
                qa_feedback["errors"].append("No valid workflows found")
        
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
    
    def run_generation(self):
        """Execute complete generation flow with canonical validation."""
        print(f"PLAYBOOK ENGINE - CANONICAL GENERATION ({self.mode.upper()} RETRIEVAL)")
        print("=" * 60)
        
        try:
            # Step A: Assert database target
            self.assert_database_target()
            
            # Step B: Load queue item
            queue_item = self.load_queue_item()
            queue_id = queue_item['id'] if queue_item else None
            
            # Step C: Load context snapshot
            context_data = self.load_context_snapshot()
            
            # Step D: Perform vector retrieval
            retrieval_result = self.perform_vector_retrieval(context_data)
            
            # Step E: Load active prompt template
            template_version = self.load_active_prompt_template()
            
            # Step F: Render prompt with retrieved evidence
            prompt = self.render_prompt(template_version, context_data, retrieval_result)
            
            # Step G: Call LLM (mock canonical)
            llm_result = self.call_llm_mock_canonical(prompt)
            
            # Step H: Persist generation run with storage guard
            generation_run_id = self.persist_generation_run_with_guard(
                queue_id, 
                template_version['id'],
                prompt,
                self.results['prompt_inputs'],
                llm_result
            )
            
            if not generation_run_id:
                print("\n[ERROR] Generation run rejected by storage guard")
                return False
            
            # Step I: Perform QA
            qa_result = self.perform_qa(generation_run_id, llm_result['parsed'])
            
            # Print summary
            print("\n" + "=" * 60)
            print("CANONICAL GENERATION COMPLETE")
            print("-" * 60)
            print(f"CVE ID: {self.cve_id}")
            print(f"Retrieval Mode: {self.mode}")
            print(f"Queue ID: {queue_id}")
            print(f"Generation Run ID: {generation_run_id}")
            print(f"Generation Status: {self.results.get('generation_status', 'unknown')}")
            print(f"QA Result: {qa_result['result']}")
            print(f"QA Score: {qa_result['score']:.3f}")
            print(f"Template Version ID: {template_version['id']}")
            print(f"Model Used: {llm_result['model']}")
            print(f"Retrieved Documents: {len(retrieval_result.get('documents', []))}")
            
            if 'validation_errors' in self.results:
                print(f"Validation Errors: {len(self.results['validation_errors'])}")
            
            print("=" * 60)
            
            return True
            
        except Exception as e:
            print(f"\n[ERROR] Generation failed: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run playbook generation with canonical validation')
    parser.add_argument('--cve', default='CVE-2025-54371',
                       help='CVE ID to process (default: CVE-2025-54371)')
    parser.add_argument('--mode', choices=['vector', 'hybrid'], default='vector',
                       help='Retrieval mode: vector or hybrid (default: vector)')
    parser.add_argument('--production', action='store_true', default=True,
                       help='Enable production mode (default: True)')
    parser.add_argument('--test', action='store_true',
                       help='Enable test mode (disables production checks)')
    
    args = parser.parse_args()
    
    production_mode = args.production and not args.test
    
    generator = CanonicalPlaybookGenerator(cve_id=args.cve, mode=args.mode, production_mode=production_mode)
    success = generator.run_generation()
    
    if success:
        print("\nCanonical generation successful!")
        sys.exit(0)
    else:
        print("\nCanonical generation failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()