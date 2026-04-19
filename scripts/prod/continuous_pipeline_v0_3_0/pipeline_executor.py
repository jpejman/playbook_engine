"""
Pipeline executor for continuous_pipeline_v0_3_0
Version: v0.3.0
Purpose:
- Reuse the v0.2.1 generation core safely
- Support evaluation-mode metadata
- Preserve explicit error visibility
- Avoid collapsing successful LLM responses into "Unknown LLM error"
"""

from __future__ import annotations

import json
import logging
import time
import traceback
from typing import Any, Dict, Optional

from .db_clients import PlaybookEngineClient
from .generation_guard import GenerationRunGuard
from .llm_client import LLMClient
from .opensearch_client import OpenSearchClient
from .generation_payload_builder import GenerationPayloadBuilder


logger = logging.getLogger(__name__)


class PipelineExecutor:
    def __init__(self):
        self.db = PlaybookEngineClient()
        self.os = OpenSearchClient()
        self.llm = LLMClient()
        self.generation_guard = GenerationRunGuard()
        self.generation_payload_builder = GenerationPayloadBuilder(self.db, self.os)

    def run(self, cve_id: str) -> Dict[str, Any]:
        """
        Backward-compatible production-style run path.
        """
        return self.execute(
            cve_id=cve_id,
            model=None,
            evaluation_mode=False,
            evaluation_batch_id=None,
            evaluation_label=None,
            creator_script="scripts.prod.continuous_pipeline_v0_3_0.pipeline_executor",
            provided_generation_payload=None,
            timeout_seconds=None,
            force=False,
        )

    def execute(
        self,
        cve_id: str,
        model: Optional[str] = None,
        evaluation_mode: bool = False,
        evaluation_batch_id: Optional[str] = None,
        evaluation_label: Optional[str] = None,
        creator_script: Optional[str] = None,
        provided_generation_payload: Optional[Dict[str, Any]] = None,
        timeout_seconds: Optional[int] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute one generation run.

        Evaluation mode:
        - allows same CVE to be processed intentionally across multiple models/batches
        - bypasses normal completed-generation skip unless caller disables force and eval logic wants to protect same batch/model

        Production mode:
        - preserves normal skip behavior via generation_guard
        """
        start_time = time.time()
        resolved_creator_script = (
            creator_script or "scripts.prod.continuous_pipeline_v0_3_0.pipeline_executor"
        )

        logger.info(
            "Starting pipeline execution for CVE: %s, model: %s, evaluation_mode: %s",
            cve_id,
            model,
            evaluation_mode,
        )

        try:
            # Stage 0: dedupe only for normal production path
            if not evaluation_mode and not force:
                if self.generation_guard.exists_completed_nonempty(cve_id):
                    logger.info(
                        "CVE %s already generated in generation_runs, skipping normal production execution",
                        cve_id,
                    )
                    return {
                        "execution_status": "completed",
                        "pipeline_status": "skipped",
                        "generation_status": "completed",
                        "generation_run_id": None,
                        "context_snapshot_id": None,
                        "retrieval_run_id": None,
                        "error": "already generated in generation_runs",
                        "evaluation_mode": evaluation_mode,
                    }

            # Stage 1: build or accept payload
            logger.info("Stage 1: Processing provided generation payload")
            generation_payload = (
                provided_generation_payload
                if provided_generation_payload is not None
                else self.generation_payload_builder.build_generation_payload(cve_id)
            )

            if not generation_payload or not isinstance(generation_payload, dict):
                raise RuntimeError("Generation payload is missing or invalid")

            cve_doc = generation_payload.get("cve_doc")
            evidence_package = generation_payload.get("evidence_package", {})
            prompt = generation_payload.get("prompt")
            debug_info = generation_payload.get("debug_info", {})

            if not prompt or not isinstance(prompt, str):
                raise RuntimeError("Generation payload missing prompt text")

            logger.info("Stage 1 complete: Payload processed")
            logger.info(
                "  Prompt builder: %s",
                debug_info.get("prompt_builder_selected", "unknown"),
            )
            logger.info("  Prompt length: %s", len(prompt))

            # Stage 2: persist context snapshot
            logger.info("Stage 2: Storing context snapshot")
            context_snapshot_id = self._store_context_snapshot(cve_id, cve_doc)
            logger.info("Stage 2 complete: context_snapshot_id=%s", context_snapshot_id)

            # Stage 3: persist retrieval evidence
            logger.info("Stage 3: Persisting retrieval run with evidence")
            retrieval_run_id = self.generation_payload_builder.evidence_packager.persist_retrieval_run(
                cve_id, evidence_package
            )
            logger.info("Stage 3 complete: retrieval_run_id=%s", retrieval_run_id)

            # Stage 4: LLM generate
            logger.info(
                "Stage 4: Generating with LLM model: %s",
                model or self.llm.default_model,
            )
            llm_response = self.llm.generate(
                prompt=prompt,
                model=model,
                timeout_seconds=timeout_seconds,
            )

            if not isinstance(llm_response, dict):
                raise RuntimeError(
                    f"LLM generate returned unexpected type: {type(llm_response).__name__}"
                )

            response_text = llm_response.get("response")
            resolved_model = llm_response.get("model") or model or self.llm.default_model

            if response_text is None:
                raise RuntimeError(
                    f"LLM generate returned payload without 'response': {json.dumps(llm_response, ensure_ascii=False)[:2000]}"
                )

            if not str(response_text).strip():
                raise RuntimeError(
                    f"LLM generate returned empty response text: {json.dumps(llm_response, ensure_ascii=False)[:2000]}"
                )

            logger.info(
                "Stage 4 complete: model=%s response_len=%s",
                resolved_model,
                len(response_text),
            )

            # Stage 5: schema validation
            logger.info("Stage 5: Validating response")
            is_valid, normalized_playbook, validation_result = (
                self.generation_payload_builder.validate_response(response_text)
            )

            logger.info("Stage 5 complete: validation_passed=%s", is_valid)
            if not is_valid:
                logger.warning(
                    "Schema validation failed: %s",
                    validation_result.get("errors", []),
                )

            # Stage 6: persist generation run with metadata
            logger.info("Stage 6: Persisting generation run")
            run_duration_seconds = round(time.time() - start_time, 3)
            generation_run_id = self._persist_generation_run(
                cve_id=cve_id,
                prompt=prompt,
                raw_response=response_text,
                model=resolved_model,
                run_duration_seconds=run_duration_seconds,
                creator_script=resolved_creator_script,
                retrieval_run_id=retrieval_run_id,
                evaluation_mode=evaluation_mode,
                evaluation_batch_id=evaluation_batch_id,
                evaluation_label=evaluation_label,
                validation_passed=is_valid,
                validation_result=validation_result,
            )
            logger.info("Stage 6 complete: generation_run_id=%s", generation_run_id)

            result = {
                "execution_status": "completed",
                "pipeline_status": "success" if is_valid else "validation_failed",
                "generation_status": "completed" if is_valid else "failed",
                "generation_run_id": generation_run_id,
                "context_snapshot_id": context_snapshot_id,
                "retrieval_run_id": retrieval_run_id,
                "response": response_text,
                "model": resolved_model,
                "run_duration_seconds": run_duration_seconds,
                "validation_passed": is_valid,
                "validation_errors": validation_result.get("errors", []),
                "validation_warnings": validation_result.get("warnings", []),
                "evaluation_mode": evaluation_mode,
                "evaluation_batch_id": evaluation_batch_id,
                "evaluation_label": evaluation_label,
                "creator_script": resolved_creator_script,
                "debug_info": debug_info,
            }

            if normalized_playbook is not None:
                result["normalized_playbook"] = normalized_playbook

            logger.info(
                "Pipeline execution completed for CVE: %s model=%s status=%s generation_run_id=%s",
                cve_id,
                resolved_model,
                result["pipeline_status"],
                generation_run_id,
            )

            return result

        except Exception as e:
            # Do not collapse real errors into "Unknown LLM error"
            logger.error("Pipeline execution failed: %s", e)
            logger.error("Traceback: %s", traceback.format_exc())
            raise

    def _store_context_snapshot(self, cve_id: str, cve_doc: Optional[Dict[str, Any]]) -> Optional[int]:
        if not cve_doc:
            logger.warning("No cve_doc available to store context snapshot for %s", cve_id)
            return None

        from .canonical_prompt_builder import CanonicalPromptBuilder

        prompt_builder = CanonicalPromptBuilder(self.db)
        normalized_context = prompt_builder._normalize_context_snapshot(cve_doc, cve_id)

        payload = {
            "cve_id": cve_id,
            "context_data": json.dumps(normalized_context),
            "created_at": self._sql_now(),
        }
        return self._safe_dynamic_insert("public.cve_context_snapshot", payload)

    def _persist_generation_run(
        self,
        cve_id: str,
        prompt: str,
        raw_response: str,
        model: str,
        run_duration_seconds: float,
        creator_script: str,
        retrieval_run_id: Optional[int],
        evaluation_mode: bool,
        evaluation_batch_id: Optional[str],
        evaluation_label: Optional[str],
        validation_passed: bool,
        validation_result: Dict[str, Any],
    ) -> Optional[int]:
        status = "completed" if validation_passed else "failed"
        generation_source = (
            "evaluation_pipeline_success" if validation_passed else "evaluation_pipeline_failed"
        )

        llm_error_info = None
        if not validation_passed:
            llm_error_info = json.dumps(
                {
                    "validation_errors": validation_result.get("errors", []),
                    "validation_warnings": validation_result.get("warnings", []),
                    "schema_compliance": validation_result.get("schema_compliance", {}),
                }
            )

        metadata = {
            "pipeline_version": "v0.3.0",
            "evaluation_mode": evaluation_mode,
            "validation_debug": validation_result.get("debug_info", {}),
        }

        insert_data = {
            "cve_id": cve_id,
            "prompt": prompt,
            "prompt_text": prompt,
            "response": raw_response,
            "raw_response": raw_response,
            "status": status,
            "generation_source": generation_source,
            "llm_error_info": llm_error_info,
            "retrieval_run_id": retrieval_run_id,
            "model": model,
            "run_duration_seconds": run_duration_seconds,
            "creator_script": creator_script,
            "evaluation_mode": evaluation_mode,
            "evaluation_batch_id": evaluation_batch_id,
            "evaluation_label": evaluation_label,
            "metadata": json.dumps(metadata),
            "created_at": self._sql_now(),
        }

        return self._safe_dynamic_insert("public.generation_runs", insert_data)

    def _safe_dynamic_insert(self, fq_table: str, data: Dict[str, Any]) -> Optional[int]:
        try:
            schema, table = fq_table.split(".", 1)
            columns = set(self.db.table_columns(schema, table))

            # Keep only valid columns and exclude placeholder sentinel from parameter binding
            filtered = {
                k: v
                for k, v in data.items()
                if k in columns and v is not None and v != self._sql_now()
            }

            has_created_at_column = "created_at" in columns
            has_created_at_data = "created_at" in data

            if has_created_at_column and has_created_at_data:
                filtered.pop("created_at", None)

                cols = list(filtered.keys())
                vals = [filtered[c] for c in cols]
                col_sql = ", ".join(cols + ["created_at"]) if cols else "created_at"
                ph_sql = ", ".join(["%s"] * len(cols) + ["NOW()"]) if cols else "NOW()"
                query = f"INSERT INTO {fq_table} ({col_sql}) VALUES ({ph_sql}) RETURNING id"
                row = self.db.execute_returning_one(query, tuple(vals))
                return int(row["id"]) if row and "id" in row else None

            inserted = self.db.insert_dynamic(fq_table, filtered, returning="id")
            return int(inserted) if inserted is not None else None

        except Exception as e:
            logger.error("_safe_dynamic_insert failed for %s: %s", fq_table, e)
            logger.error("Data keys: %s", sorted(data.keys()))
            logger.error("Traceback: %s", traceback.format_exc())
            return None

    @staticmethod
    def _sql_now() -> str:
        return "__SQL_NOW__"