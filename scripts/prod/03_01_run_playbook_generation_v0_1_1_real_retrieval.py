from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

import argparse
import json
import logging
import os
import time
from typing import Any, Dict, Optional

import psycopg2
import psycopg2.extras
from psycopg2.extras import Json

from src.utils.db import DatabaseClient
from src.retrieval.evidence_collector import EvidenceCollector
from src.retrieval.prompt_input_builder import PromptInputBuilder
from src.utils.llm_client import LLMClient
from src.utils.playbook_parser import parse_playbook_response

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RealRetrievalPlaybookGenerator:
    def __init__(self, cve_id: str):
        self.cve_id = cve_id
        self.db = DatabaseClient()
        self.llm_client = LLMClient()
        self.model = os.getenv("LLM_MODEL", "gemma3:4b")
        logger.info("RealRetrievalPlaybookGenerator initialized for %s", self.cve_id)

    def _load_context_snapshot(self) -> Dict[str, Any]:
        logger.info("Loading context snapshot for %s...", self.cve_id)
        row = self.db.fetch_one(
            """
            SELECT *
            FROM cve_context_snapshot
            WHERE cve_id = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (self.cve_id,),
        )
        if not row:
            raise RuntimeError(f"No context snapshot found for {self.cve_id}")
        logger.info("Found context snapshot ID: %s", row["id"])
        return row

    def _load_active_prompt_template_version(self) -> Dict[str, Any]:
        row = self.db.fetch_one(
            """
            SELECT
                ptv.*,
                pt.name AS template_name
            FROM prompt_template_versions ptv
            JOIN prompt_templates pt
              ON ptv.template_id = pt.id
            WHERE ptv.is_active = TRUE
            ORDER BY ptv.id DESC
            LIMIT 1
            """
        )
        if not row:
            raise RuntimeError("No active prompt template version found")
        logger.info("Found active template version ID: %s", row["id"])
        return row

    def _persist_retrieval_run(
        self,
        retrieved_context: Dict[str, Any],
        source_indexes: list[str],
    ) -> Optional[int]:
        logger.info("Persisting retrieval run...")
        with self.db.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO retrieval_runs (
                        cve_id,
                        retrieved_context,
                        source_indexes,
                        created_at
                    )
                    VALUES (%s, %s, %s, NOW())
                    RETURNING id
                    """,
                    (
                        self.cve_id,
                        Json(retrieved_context),
                        source_indexes,
                    ),
                )
                result = cur.fetchone()
                conn.commit()
        
        if result and "id" in result:
            retrieval_run_id = result["id"]
            logger.info("Created retrieval run ID: %s", retrieval_run_id)
            return retrieval_run_id
        
        logger.error("Failed to get retrieval run ID from database")
        return None

    def _persist_retrieval_documents(
        self,
        retrieval_run_id: int,
        evidence_items: list[Dict[str, Any]],
    ) -> int:
        logger.info("Persisting retrieval documents...")
        count = 0
        with self.db.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                for idx, item in enumerate(evidence_items, start=1):
                    cur.execute(
                        """
                        INSERT INTO retrieval_documents (
                            retrieval_run_id,
                            doc_id,
                            content,
                            metadata,
                            score,
                            rank,
                            created_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, NOW())
                        """,
                        (
                            retrieval_run_id,
                            item.get("doc_id") or item.get("id") or f"{self.cve_id}-doc-{idx}",
                            item.get("content") or json.dumps(item),
                            Json(item.get("metadata", {})),
                            item.get("score"),
                            idx,
                        ),
                    )
                    count += 1
                conn.commit()
        logger.info("Persisted %s retrieval documents", count)
        return count

    def _call_llm(self, prompt: str) -> Dict[str, Any]:
        logger.info("Calling real LLM API...")
        llm_start_time = time.time()
        llm_result = self.llm_client.generate(prompt)
        llm_time = time.time() - llm_start_time

        logger.info("LLM API call completed in %.2fs, status: %s", llm_time, llm_result.get("status"))

        if llm_result.get("status") == "completed":
            raw_text = llm_result.get("raw_text", "")
            model_used = llm_result.get("model", self.llm_client.model)

            logger.info("LLM response received: %s chars", len(raw_text))
            logger.info("Model used: %s", model_used)

            parser_result = parse_playbook_response(raw_text)

            return {
                "raw": raw_text,
                "parsed": parser_result.get("parsed_playbook"),
                "model": model_used,
                "parse_ok": parser_result.get("parsed_ok", False),
                "parse_errors": parser_result.get("parse_errors", []),
                "status": "completed",
            }

        error_msg = llm_result.get("error", "Unknown error")
        logger.error("LLM generation failed: %s", error_msg)

        return {
            "raw": "",
            "parsed": None,
            "model": self.llm_client.model,
            "parse_ok": False,
            "parse_errors": [f"LLM API error: {error_msg}"],
            "status": "failed",
        }

    def _persist_generation_run(self, prompt: str, llm_result: Dict[str, Any], retrieval_run_id: Optional[int]) -> Optional[int]:
        logger.info("Persisting generation run...")

        if llm_result.get("parse_ok", False) and llm_result.get("raw"):
            status = "completed"
            generation_source = "live_llm_success"
            llm_error_info = None
            response_text = llm_result["raw"]
        else:
            status = "failed"
            generation_source = "live_llm_failed"
            llm_error_info = json.dumps({
                "parse_errors": llm_result.get("parse_errors", []),
                "llm_error": llm_result.get("parse_errors", ["Unknown error"])[0] if llm_result.get("parse_errors") else "LLM call failed",
                "has_raw_response": bool(llm_result.get("raw")),
                "parse_ok": llm_result.get("parse_ok", False),
            })
            response_text = llm_result.get("raw", "")

        logger.info("Generation attempted: true")
        logger.info("Status determined: %s", status)
        logger.info("Generation source: %s", generation_source)
        logger.info("Response length: %s chars", len(response_text))

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
                logger.info("Available columns in generation_runs: %s", columns)

                # Build insert query based on available columns
                if 'retrieval_run_id' in columns and 'generation_source' in columns and 'llm_error_info' in columns:
                    cur.execute(
                        """
                        INSERT INTO generation_runs (
                            cve_id, retrieval_run_id, prompt, response, model, status,
                            generation_source, llm_error_info, created_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                        RETURNING id
                        """,
                        (
                            self.cve_id,
                            retrieval_run_id,
                            prompt,
                            response_text,
                            llm_result["model"],
                            status,
                            generation_source,
                            llm_error_info,
                        ),
                    )
                elif 'retrieval_run_id' in columns and 'prompt' in columns and 'response' in columns:
                    cur.execute(
                        """
                        INSERT INTO generation_runs (
                            cve_id, retrieval_run_id, prompt, response, model, status
                        )
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id
                        """,
                        (
                            self.cve_id,
                            retrieval_run_id,
                            prompt,
                            response_text,
                            llm_result["model"],
                            status,
                        ),
                    )
                elif 'prompt' in columns and 'response' in columns:
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
                            response_text,
                            llm_result["model"],
                            status,
                        ),
                    )
                elif 'cve_id' in columns:
                    cur.execute(
                        """
                        INSERT INTO generation_runs (cve_id, status)
                        VALUES (%s, %s)
                        RETURNING id
                        """,
                        (self.cve_id, status),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO generation_runs DEFAULT VALUES
                        RETURNING id
                        """
                    )

                result = cur.fetchone()
                conn.commit()

        if result and "id" in result:
            generation_run_id = result["id"]
            logger.info("Inserted generation_run_id: %s", generation_run_id)
            logger.info("Final generation status: %s", status)
            if llm_error_info:
                logger.info("LLM error info stored: %s", llm_error_info[:200])
            return generation_run_id

        raise ValueError("Failed to get generation run ID from database")

    def run(self) -> Dict[str, Any]:
        retrieval_run_id: Optional[int] = None
        generation_run_id: Optional[int] = None

        try:
            logger.info("PLAYBOOK ENGINE - REAL RETRIEVAL")
            logger.info("============================================================")

            context_snapshot = self._load_context_snapshot()

            logger.info("Collecting evidence...")
            collector = EvidenceCollector(
                cve_id=self.cve_id,
                context_snapshot=context_snapshot,
            )
            evidence_package = collector.collect_all_evidence()

            evidence_items = evidence_package.get("retrieved_evidence", []) or evidence_package.get("evidence", [])
            source_indexes = evidence_package.get("source_indexes", []) or list(
                {
                    item.get("source")
                    or item.get("source_index")
                    or item.get("index")
                    for item in evidence_items
                    if isinstance(item, dict)
                }
            )
            source_indexes = [s for s in source_indexes if s]

            retrieval_run_id = self._persist_retrieval_run(
                retrieved_context=evidence_package,
                source_indexes=source_indexes,
            )

            if retrieval_run_id is not None and evidence_items:
                self._persist_retrieval_documents(retrieval_run_id, evidence_items)

            template = self._load_active_prompt_template_version()

            logger.info("Building complete prompt input package...")
            builder = PromptInputBuilder(
                cve_id=self.cve_id,
                context_snapshot=context_snapshot,
                evidence_collector=collector,
                template_data=template,
            )
            input_package = builder.build_input_package()
            prompt = builder.render_prompt(input_package)

            llm_result = self._call_llm(prompt)
            generation_run_id = self._persist_generation_run(prompt, llm_result, retrieval_run_id)

            return {
                "generation_run_id": generation_run_id,
                "status": "completed" if llm_result.get("parse_ok", False) and llm_result.get("raw") else "failed",
                "error": None if llm_result.get("parse_ok", False) and llm_result.get("raw") else (llm_result.get("parse_errors", ["Unknown error"])[0] if llm_result.get("parse_errors") else "LLM call failed"),
                "retrieval_run_id": retrieval_run_id,
                "qa_run_id": None,
                "qa_result": None,
                "qa_score": None,
            }

        except Exception as exc:
            error_message = f"Generation pipeline exception: {exc}"
            logger.exception("Generation pipeline exception")
            return {
                "generation_run_id": None,
                "status": "failed",
                "error": error_message,
                "retrieval_run_id": retrieval_run_id,
                "qa_run_id": None,
                "qa_result": None,
                "qa_score": None,
            }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", required=True)
    args = parser.parse_args()

    generator = RealRetrievalPlaybookGenerator(args.cve)
    result = generator.run()
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()