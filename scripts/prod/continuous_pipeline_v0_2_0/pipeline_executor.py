"""
Internal pipeline executor
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
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
from .prompt_builder import PromptBuilder


class PipelineExecutor:
    def __init__(self):
        self.db = PlaybookEngineClient()
        self.os = OpenSearchClient()
        self.llm = LLMClient()
        self.prompt_builder = PromptBuilder()
        self.generation_guard = GenerationRunGuard()
        self.logger = logging.getLogger(__name__)

    def run(self, cve_id: str) -> dict[str, Any]:
        self.logger.info(f"Starting pipeline execution for CVE: {cve_id}")
        
        try:
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

            self.logger.info(f"Stage 1: Fetching CVE from OpenSearch")
            cve_doc = self.os.fetch_cve(cve_id)
            self.logger.info(f"Stage 1 complete: Retrieved CVE document with {len(cve_doc)} fields")
            
            self.logger.info(f"Stage 2: Storing context snapshot")
            context_snapshot_id = self._store_context_snapshot(cve_id, cve_doc)
            self.logger.info(f"Stage 2 complete: context_snapshot_id={context_snapshot_id}")
            
            self.logger.info(f"Stage 3: Storing retrieval run")
            retrieval_run_id = self._store_retrieval(cve_id, cve_doc)
            self.logger.info(f"Stage 3 complete: retrieval_run_id={retrieval_run_id}")
            
            self.logger.info(f"Stage 4: Building prompt")
            prompt = self.prompt_builder.build(cve_doc)
            self.logger.info(f"Stage 4 complete: prompt length={len(prompt)}")
            
            self.logger.info(f"Stage 5: Storing generation start")
            generation_run_id = self._store_generation_started(cve_id, prompt, context_snapshot_id)
            self.logger.info(f"Stage 5 complete: generation_run_id={generation_run_id}")
            
            self.logger.info(f"Stage 6: Calling LLM")
            llm_response = self.llm.generate(prompt)
            response_text = llm_response.get('response') or json.dumps(llm_response)
            self.logger.info(f"Stage 6 complete: LLM response length={len(response_text)}")
            
            self.logger.info(f"Stage 7: Marking generation completed")
            self._mark_generation_completed(generation_run_id, response_text)
            self.logger.info(f"Stage 7 complete: Generation marked completed")
            
            self.logger.info(f"Pipeline execution successful for CVE: {cve_id}")
            return {
                'execution_status': 'completed',
                'pipeline_status': 'success',
                'generation_status': 'completed',
                'generation_run_id': generation_run_id,
                'context_snapshot_id': context_snapshot_id,
                'retrieval_run_id': retrieval_run_id,
                'response': response_text,
            }
        except Exception as e:
            self.logger.error(f"Pipeline execution failed for CVE {cve_id}: {e}")
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def _store_context_snapshot(self, cve_id: str, cve_doc: dict[str, Any]) -> int | None:
        payload = {
            'cve_id': cve_id,
            'context_data': json.dumps(cve_doc),
            'created_at': self._sql_now(),
        }
        return self._safe_dynamic_insert('public.cve_context_snapshot', payload)

    def _store_retrieval(self, cve_id: str, cve_doc: dict[str, Any]) -> int | None:
        retrieval_run_id = self._safe_dynamic_insert(
            'public.retrieval_runs',
            {
                'cve_id': cve_id,
                'status': 'completed',
                'source': 'opensearch_nvd',
                'created_at': self._sql_now(),
            },
        )
        if retrieval_run_id is not None:
            self._safe_dynamic_insert(
                'public.retrieval_documents',
                {
                    'run_id': retrieval_run_id,
                    'retrieval_run_id': retrieval_run_id,
                    'cve_id': cve_id,
                    'source': 'opensearch_nvd',
                    'document_id': cve_doc.get('source_doc_id'),
                    'content': json.dumps(cve_doc),
                    'content_text': json.dumps(cve_doc),
                    'metadata_json': json.dumps({'references': cve_doc.get('references', [])}),
                    'created_at': self._sql_now(),
                },
            )
        return retrieval_run_id

    def _store_generation_started(self, cve_id: str, prompt: str, context_snapshot_id: int | None) -> int:
        payload = {
            'cve_id': cve_id,
            'status': 'running',
            'prompt_text': prompt,
            'prompt': prompt,
            'generation_source': 'continuous_pipeline_v0_2_0',
            'context_snapshot_id': context_snapshot_id,
            'created_at': self._sql_now(),
        }
        generation_run_id = self._safe_dynamic_insert('public.generation_runs', payload)
        if generation_run_id is None:
            raise RuntimeError('Failed to persist generation_runs start record')
        return int(generation_run_id)

    def _mark_generation_completed(self, generation_run_id: int, response_text: str):
        available = set(self.db.table_columns('public', 'generation_runs'))
        updates = []
        params: list[Any] = []
        for col, value in [
            ('status', 'completed'),
            ('response', response_text),
            ('raw_response', response_text),
            ('pipeline_status', 'success'),
            ('updated_at', self._sql_now()),
            ('completed_at', self._sql_now()),
        ]:
            if col in available:
                if value == self._sql_now():
                    updates.append(f"{col} = NOW()")
                else:
                    updates.append(f"{col} = %s")
                    params.append(value)
        if not updates:
            raise RuntimeError('generation_runs has no updateable completion columns')
        params.append(generation_run_id)
        self.db.execute(f"UPDATE public.generation_runs SET {', '.join(updates)} WHERE id = %s", tuple(params))

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
