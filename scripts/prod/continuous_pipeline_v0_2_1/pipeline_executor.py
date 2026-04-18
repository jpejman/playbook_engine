"""
Internal pipeline executor with canonical generation path
Version: v0.2.1_canonical
Timestamp (UTC): 2026-04-17T14:36:53Z

Purpose:
- Use canonical prompt builder and schema from Phase 1 runner
- Ensure prompt/schema convergence between pipelines
- Maintain same queueing, claiming, and persistence behavior
"""

from __future__ import annotations

import json
import logging
import traceback
from typing import Any

from .db_clients import PlaybookEngineClient
from .generation_guard import GenerationRunGuard
from .llm_client import LLMClient
from .opensearch_client import OpenSearchClient
from .generation_payload_builder import GenerationPayloadBuilder


class PipelineExecutor:
    def __init__(self):
        self.db = PlaybookEngineClient()
        self.os = OpenSearchClient()
        self.llm = LLMClient()
        self.generation_guard = GenerationRunGuard()
        self.generation_payload_builder = GenerationPayloadBuilder(self.db, self.os)
        self.logger = logging.getLogger(__name__)

    def run(self, cve_id: str) -> dict[str, Any]:
        self.logger.info(f"Starting canonical pipeline execution for CVE: {cve_id}")
        
        try:
            # Check if already generated (guard)
            if self.generation_guard.exists_completed_nonempty(cve_id):
                self.logger.info(f"CVE {cve_id} already generated in generation_runs, skipping")
                return {
                    'execution_status': 'completed',
                    'pipeline_status': 'skipped',
                    'generation_status': 'completed',
                    'generation_run_id': None,
                    'context_snapshot_id': None,
                    'retrieval_run_id': None,
                    'error': 'already generated in generation_runs',
                }

            self.logger.info(f"Stage 1: Building canonical generation payload")
            generation_payload = self.generation_payload_builder.build_generation_payload(cve_id)
            cve_doc = generation_payload['cve_doc']
            evidence_package = generation_payload['evidence_package']
            prompt = generation_payload['prompt']
            debug_info = generation_payload['debug_info']
            
            # Log debug info
            self.logger.info(f"Stage 1 complete: Canonical payload built")
            self.logger.info(f"  Prompt builder: {debug_info.get('prompt_builder_selected')}")
            self.logger.info(f"  Schema module: {debug_info.get('schema_module_selected')}")
            self.logger.info(f"  Prompt length: {debug_info.get('prompt_length')} chars")
            self.logger.info(f"  Evidence count: {debug_info.get('evidence_count')}")
            self.logger.info(f"  Retrieval decision: {debug_info.get('retrieval_decision')}")
            
            self.logger.info(f"Stage 2: Storing context snapshot")
            context_snapshot_id = self._store_context_snapshot(cve_id, cve_doc)
            self.logger.info(f"Stage 2 complete: context_snapshot_id={context_snapshot_id}")
            
            self.logger.info(f"Stage 3: Persisting retrieval run with evidence")
            retrieval_run_id = self.generation_payload_builder.evidence_packager.persist_retrieval_run(
                cve_id, evidence_package
            )
            self.logger.info(f"Stage 3 complete: retrieval_run_id={retrieval_run_id}")
            
            self.logger.info(f"Stage 4: Calling LLM with canonical prompt")
            llm_response = self.llm.generate(prompt)
            response_text = llm_response.get('response') or json.dumps(llm_response)
            self.logger.info(f"Stage 4 complete: LLM response length={len(response_text)}")
            
            self.logger.info(f"Stage 5: Validating response against canonical schema")
            is_valid, normalized_playbook, validation_result = self.generation_payload_builder.validate_response(
                response_text
            )
            self.logger.info(f"Stage 5 complete: Validation passed={is_valid}")
            
            if not is_valid:
                self.logger.warning(f"Schema validation failed: {validation_result.get('errors', [])}")
            
            self.logger.info(f"Stage 6: Persisting generation run")
            generation_run_id = self.generation_payload_builder.persist_generation_run(
                cve_id=cve_id,
                prompt=prompt,
                raw_response=response_text,
                validation_result=validation_result,
                retrieval_run_id=retrieval_run_id
            )
            self.logger.info(f"Stage 6 complete: generation_run_id={generation_run_id}")
            
            # Build result
            result = {
                'execution_status': 'completed',
                'pipeline_status': 'success' if is_valid else 'validation_failed',
                'generation_status': 'completed' if is_valid else 'failed',
                'generation_run_id': generation_run_id,
                'context_snapshot_id': context_snapshot_id,
                'retrieval_run_id': retrieval_run_id,
                'response': response_text,
                'validation_passed': is_valid,
                'validation_errors': validation_result.get('errors', []),
                'validation_warnings': validation_result.get('warnings', []),
                'debug_info': debug_info
            }
            
            if is_valid and normalized_playbook:
                result['normalized_playbook'] = normalized_playbook
            
            self.logger.info(f"Canonical pipeline execution completed for CVE: {cve_id}")
            self.logger.info(f"  Generation run ID: {generation_run_id}")
            self.logger.info(f"  Validation passed: {is_valid}")
            self.logger.info(f"  Schema compliance: {validation_result.get('schema_compliance', {})}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Canonical pipeline execution failed for CVE {cve_id}: {e}")
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def _store_context_snapshot(self, cve_id: str, cve_doc: dict[str, Any]) -> int | None:
        # Use the canonical prompt builder to normalize context
        from .canonical_prompt_builder import CanonicalPromptBuilder
        prompt_builder = CanonicalPromptBuilder(self.db)
        normalized_context = prompt_builder._normalize_context_snapshot(cve_doc, cve_id)
        
        payload = {
            'cve_id': cve_id,
            'context_data': json.dumps(normalized_context),
            'created_at': self._sql_now(),
        }
        return self._safe_dynamic_insert('public.cve_context_snapshot', payload)

    # Note: The following methods are no longer used in the canonical path:
    # - _store_retrieval: Replaced by evidence_packager.persist_retrieval_run
    # - _store_generation_started: Replaced by generation_payload_builder.persist_generation_run
    # - _mark_generation_completed: Replaced by generation_payload_builder.persist_generation_run
    
    # These methods are kept for backward compatibility but not called in the canonical path

    def _safe_dynamic_insert(self, fq_table: str, data: dict[str, Any]) -> int | None:
        try:
            self.logger.debug(f"Attempting dynamic insert into {fq_table} with {len(data)} fields")
            schema, table = fq_table.split('.', 1)
            columns = set(self.db.table_columns(schema, table))
            self.logger.debug(f"Table {fq_table} has columns: {sorted(columns)}")
            
            # Filter data to only include columns that exist in the table
            filtered = {k: v for k, v in data.items() if k in columns and v is not None and v != self._sql_now()}
            self.logger.debug(f"Filtered to {len(filtered)} matching columns: {sorted(filtered.keys())}")
            
            # Handle created_at specially - use NOW() instead of the placeholder
            has_created_at_column = 'created_at' in columns
            has_created_at_data = 'created_at' in data
            
            if has_created_at_column and has_created_at_data:
                # Don't include created_at in filtered since we'll handle it specially
                if 'created_at' in filtered:
                    del filtered['created_at']
                
                cols = list(filtered.keys())
                vals = [filtered[c] for c in cols]
                col_sql = ', '.join(cols + ['created_at']) if cols else 'created_at'
                ph_sql = ', '.join(['%s'] * len(cols) + ['NOW()']) if cols else 'NOW()'
                query = f"INSERT INTO {fq_table} ({col_sql}) VALUES ({ph_sql}) RETURNING id"
                self.logger.debug(f"Executing query: {query}")
                row = self.db.execute_returning_one(query, tuple(vals))
                result = int(row['id']) if row and 'id' in row else None
                self.logger.debug(f"Insert result: {result}")
                return result
            else:
                # No created_at to handle specially, use regular insert_dynamic
                try:
                    inserted = self.db.insert_dynamic(fq_table, filtered, returning='id')
                    result = int(inserted) if inserted is not None else None
                    self.logger.debug(f"Insert dynamic result: {result}")
                    return result
                except Exception as e:
                    self.logger.error(f"Dynamic insert failed for {fq_table}: {e}")
                    self.logger.error(f"Data keys: {sorted(data.keys())}")
                    self.logger.error(f"Table columns: {sorted(columns)}")
                    raise
        except Exception as e:
            self.logger.error(f"_safe_dynamic_insert failed for {fq_table}: {e}")
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            return None

    @staticmethod
    def _sql_now() -> str:
        return '__SQL_NOW__'
