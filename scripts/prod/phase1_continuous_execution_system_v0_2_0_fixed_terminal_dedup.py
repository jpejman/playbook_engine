#!/usr/bin/env python3
"""
VS.ai — Playbook Engine Gen-3
Phase 1 Continuous Execution System
Directive Pack v0.2.0 — Continuous Runner + Queue Draining + Parallel Safety
Version: v0.2.0
Timestamp (UTC): 2026-04-10

OBJECTIVE

Extend the current Phase 1 single-CVE runner into a controlled continuous execution system that:
- processes one CVE at a time
- can run consecutively without manual restarts
- drains eligible work safely
- avoids duplicate parallel execution
- stores structured session and run records

IMPLEMENTATION ORDER

1. Continuous Runner Loop
2. Queue Draining Mode
3. Parallel Safety Locking
4. Continuous Run Records Dump
5. Resume-Safe Continuous Execution
6. End-of-Session Summary

RULES

- OpenSearch cve index remains the only CVE source
- PostgreSQL remains state/persistence layer only
- no prompt changes
- no QA logic redesign
- no parser redesign in this directive pack
- process one CVE at a time internally
- all artifacts must include timestamps
- all artifacts must include run_id and session_id
"""

import sys
import json
import uuid
import time
import signal
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
from enum import Enum
from concurrent.futures import TimeoutError as FutureTimeoutError
from concurrent.futures import ThreadPoolExecutor

# Keep this for compatibility when running as a script file directly.
# Module-mode execution (`python -m ...`) does not require it.
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.retrieval.opensearch_client import RealOpenSearchClient
from src.utils.db import DatabaseClient
from scripts.prod.time_utils import get_utc_now, datetime_to_iso, calculate_duration_seconds
from scripts.prod.phase1_selector_corrected import Phase1CVESelectorCorrected
from scripts.prod.phase1_direct_cve_runner import Phase1DirectCVERunner

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/continuous_runner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class RunMode(Enum):
    SINGLE_RUN = "single_run"
    CONTINUOUS = "continuous"
    DRAIN_QUEUE = "drain_queue"


class ExecutionStatus(Enum):
    STARTED = "started"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
    LOCKED = "locked"


class ParallelSafetyLock:
    def __init__(self, db: DatabaseClient):
        self.db = db
        self.lock_table = "continuous_execution_locks"
        self._ensure_lock_table()

    def _ensure_lock_table(self):
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {self.lock_table} (
            id SERIAL PRIMARY KEY,
            session_id VARCHAR(64) NOT NULL,
            run_id VARCHAR(64) NOT NULL,
            cve_id VARCHAR(50),
            status VARCHAR(20) NOT NULL,
            lock_acquired_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            lock_released_at TIMESTAMP WITH TIME ZONE,
            lock_timeout_seconds INTEGER DEFAULT 300,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            UNIQUE(session_id, run_id)
        )
        """
        self.db.execute(create_table_sql)
        self.db.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.lock_table}_status ON {self.lock_table}(status)")
        self.db.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.lock_table}_cve_id ON {self.lock_table}(cve_id)")

    def acquire_lock(self, session_id: str, run_id: str, cve_id: Optional[str] = None) -> bool:
        try:
            self.cleanup_stale_locks(5)

            check_sql = f"""
            SELECT COUNT(*) as active_locks 
            FROM {self.lock_table} 
            WHERE status = 'running' 
            AND lock_released_at IS NULL
            """
            result = self.db.fetch_one(check_sql)

            if result and result['active_locks'] > 0:
                logger.warning("Active lock detected - parallel execution prevented")
                return False

            if cve_id:
                cve_check_sql = f"""
                SELECT COUNT(*) as cve_locks 
                FROM {self.lock_table} 
                WHERE cve_id = %s 
                AND status = 'running' 
                AND lock_released_at IS NULL
                """
                cve_result = self.db.fetch_one(cve_check_sql, (cve_id,))

                if cve_result and cve_result['cve_locks'] > 0:
                    logger.warning(f"Active lock detected for CVE {cve_id} - parallel execution prevented")
                    return False

            insert_sql = f"""
            INSERT INTO {self.lock_table} (session_id, run_id, cve_id, status, lock_acquired_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (session_id, run_id) DO UPDATE 
            SET status = EXCLUDED.status,
                lock_acquired_at = NOW(),
                lock_released_at = NULL
            RETURNING id
            """

            try:
                result = self.db.fetch_one(insert_sql, (session_id, run_id, cve_id, ExecutionStatus.RUNNING.value))
                if result:
                    logger.info(f"Lock acquired for session={session_id}, run={run_id}, cve={cve_id}")
                    return True
                logger.warning("Lock insert returned no result")
                return False
            except Exception as e:
                logger.error(f"Lock insert failed: {e}")
                return False

        except Exception as e:
            logger.error(f"Failed to acquire lock: {e}")
            return False

    def release_lock(self, session_id: str, run_id: str, status: ExecutionStatus = ExecutionStatus.COMPLETED):
        try:
            update_sql = f"""
            UPDATE {self.lock_table} 
            SET status = %s, lock_released_at = NOW()
            WHERE session_id = %s AND run_id = %s
            """
            self.db.execute(update_sql, (status.value, session_id, run_id))
            logger.info(f"Lock released for session={session_id}, run={run_id}")
        except Exception as e:
            logger.error(f"Failed to release lock: {e}")

    def cleanup_stale_locks(self, timeout_minutes: int = 10):
        try:
            cleanup_sql = f"""
            UPDATE {self.lock_table} 
            SET status = 'stopped', lock_released_at = NOW()
            WHERE status = 'running' 
            AND lock_acquired_at < NOW() - INTERVAL '%s minutes'
            """
            result = self.db.execute(cleanup_sql, (timeout_minutes,))
            if result:
                logger.info(f"Cleaned up {result} stale locks")
        except Exception as e:
            logger.error(f"Failed to cleanup stale locks: {e}")


class ContinuousRunRecords:
    def __init__(self, db: DatabaseClient):
        self.db = db
        self.records_table = "continuous_run_records"
        self._ensure_records_table()

    def _ensure_records_table(self):
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {self.records_table} (
            id SERIAL PRIMARY KEY,
            session_id VARCHAR(64) NOT NULL,
            run_id VARCHAR(64) NOT NULL,
            run_number INTEGER NOT NULL,
            cve_id VARCHAR(50) NOT NULL,
            start_time TIMESTAMP WITH TIME ZONE NOT NULL,
            end_time TIMESTAMP WITH TIME ZONE,
            duration_seconds FLOAT,
            status VARCHAR(20) NOT NULL,
            context_snapshot_id INTEGER,
            generation_run_id INTEGER,
            qa_result VARCHAR(20),
            qa_score FLOAT,
            errors JSONB,
            metadata JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            UNIQUE(session_id, run_id)
        )
        """
        self.db.execute(create_table_sql)
        self.db.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.records_table}_session ON {self.records_table}(session_id)")
        self.db.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.records_table}_cve_id ON {self.records_table}(cve_id)")
        self.db.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.records_table}_status ON {self.records_table}(status)")
        self.db.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.records_table}_start_time ON {self.records_table}(start_time)")

    def start_run(self, session_id: str, run_id: str, run_number: int, cve_id: str) -> bool:
        try:
            insert_sql = f"""
            INSERT INTO {self.records_table} 
            (session_id, run_id, run_number, cve_id, start_time, status)
            VALUES (%s, %s, %s, %s, NOW(), %s)
            """
            self.db.execute(insert_sql, (session_id, run_id, run_number, cve_id, ExecutionStatus.STARTED.value))
            logger.info(f"Run {run_number} started for CVE {cve_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to start run record: {e}")
            return False

    def complete_run(
        self,
        session_id: str,
        run_id: str,
        cve_id: str,
        status: ExecutionStatus,
        context_snapshot_id: Optional[int] = None,
        generation_run_id: Optional[int] = None,
        qa_result: Optional[str] = None,
        qa_score: Optional[float] = None,
        errors: Optional[List[str]] = None,
        metadata: Optional[Dict] = None,
    ):
        try:
            start_sql = f"""
            SELECT start_time FROM {self.records_table} 
            WHERE session_id = %s AND run_id = %s AND cve_id = %s
            """
            start_record = self.db.fetch_one(start_sql, (session_id, run_id, cve_id))

            duration = None
            if start_record and start_record["start_time"]:
                start_time = start_record["start_time"]
                duration = (datetime.now(start_time.tzinfo) - start_time).total_seconds()

            update_sql = f"""
            UPDATE {self.records_table} 
            SET end_time = NOW(),
                duration_seconds = %s,
                status = %s,
                context_snapshot_id = %s,
                generation_run_id = %s,
                qa_result = %s,
                qa_score = %s,
                errors = %s,
                metadata = %s
            WHERE session_id = %s AND run_id = %s AND cve_id = %s
            """

            self.db.execute(
                update_sql,
                (
                    duration,
                    status.value,
                    context_snapshot_id,
                    generation_run_id,
                    qa_result,
                    qa_score,
                    json.dumps(errors) if errors else None,
                    json.dumps(metadata) if metadata else None,
                    session_id,
                    run_id,
                    cve_id,
                ),
            )

            logger.info(f"Run {run_id} completed with status {status.value}")
        except Exception as e:
            logger.error(f"Failed to complete run record: {e}")

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        try:
            summary_sql = f"""
            SELECT 
                COUNT(*) as total_runs,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_runs,
                COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_runs,
                COUNT(CASE WHEN status = 'stopped' THEN 1 END) as stopped_runs,
                MIN(start_time) as session_start,
                MAX(end_time) as session_end,
                AVG(duration_seconds) as avg_duration,
                SUM(duration_seconds) as total_duration
            FROM {self.records_table}
            WHERE session_id = %s
            """
            result = self.db.fetch_one(summary_sql, (session_id,))

            if result:
                result["total_runs"] = result.get("total_runs") or 0
                result["completed_runs"] = result.get("completed_runs") or 0
                result["failed_runs"] = result.get("failed_runs") or 0
                result["stopped_runs"] = result.get("stopped_runs") or 0
                result["avg_duration"] = result.get("avg_duration") or 0.0
                result["total_duration"] = result.get("total_duration") or 0.0
            else:
                result = {
                    "total_runs": 0,
                    "completed_runs": 0,
                    "failed_runs": 0,
                    "stopped_runs": 0,
                    "session_start": None,
                    "session_end": None,
                    "avg_duration": 0.0,
                    "total_duration": 0.0,
                }

            cves_sql = f"""
            SELECT cve_id, status, start_time, end_time, duration_seconds
            FROM {self.records_table}
            WHERE session_id = %s
            ORDER BY start_time
            """
            cves = self.db.fetch_all(cves_sql, (session_id,))

            return {
                "session_id": session_id,
                "summary": result,
                "processed_cves": cves or [],
            }
        except Exception as e:
            logger.error(f"Failed to get session summary: {e}")
            return {
                "session_id": session_id,
                "summary": {
                    "total_runs": 0,
                    "completed_runs": 0,
                    "failed_runs": 0,
                    "stopped_runs": 0,
                    "session_start": None,
                    "session_end": None,
                    "avg_duration": 0.0,
                    "total_duration": 0.0,
                },
                "processed_cves": [],
            }


class Phase1ContinuousExecutionSystem:
    def __init__(
        self,
        mode: RunMode = RunMode.SINGLE_RUN,
        max_runs: int = 0,
        timeout_minutes: int = 30,
        batch_size: int = 10,
        wait_seconds: int = 5,
    ):
        self.mode = mode
        self.max_runs = max_runs
        self.timeout_minutes = timeout_minutes
        self.batch_size = batch_size
        self.wait_seconds = wait_seconds
        self.session_id = str(uuid.uuid4())
        self.session_start_time = get_utc_now()
        self.run_counter = 0
        self.should_stop = False
        self.session_processed_cves = set()

        self.db = DatabaseClient()
        self.lock_manager = ParallelSafetyLock(self.db)
        self.records_manager = ContinuousRunRecords(self.db)

        self.lock_manager.cleanup_stale_locks()

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        logger.info("Continuous Execution System initialized")
        logger.info(f"Session ID: {self.session_id}")
        logger.info(f"Mode: {self.mode.value}")
        logger.info(f"Max runs: {self.max_runs if self.max_runs > 0 else 'unlimited'}")
        logger.info(f"Timeout per CVE run: {timeout_minutes} minutes")
        logger.info(f"Batch size: {self.batch_size}")
        logger.info(f"Wait between runs: {self.wait_seconds} seconds")
        logger.info("Session-level deduplication enabled")

    def _signal_handler(self, signum, frame):
        logger.info(f"Received shutdown signal {signum}")
        self.should_stop = True

    def _generate_run_id(self) -> str:
        self.run_counter += 1
        return f"{self.session_id}-run-{self.run_counter:04d}"

    def _has_terminal_success(self, cve_id: str) -> bool:
        """
        Treat a CVE as terminal for selection if playbook_engine already contains
        a non-empty generated playbook in generation_runs, regardless of QA state.
        QA is downstream only and must not gate reselection.
        """
        row = self.db.fetch_one(
            """
            SELECT 1
            FROM generation_runs gr
            WHERE gr.cve_id = %s
            AND gr.status = 'completed'
            AND gr.response IS NOT NULL
            AND btrim(gr.response) <> ''
            LIMIT 1
            """,
            (cve_id,),
        )

        return row is not None

    def _normalize_candidate_ids(self, selection_results: Dict[str, Any]) -> List[str]:
        candidates = selection_results.get("eligible_candidates", []) or []
        out: List[str] = []
        for item in candidates:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                cve_id = item.get("cve_id") or item.get("id")
                if cve_id:
                    out.append(cve_id)
        return out

    def _select_fresh_cve_phase1(self, limit: int = 100) -> Optional[Dict[str, Any]]:
        try:
            selector = Phase1CVESelectorCorrected()
            selection_results = selector.run_selection_corrected(limit)

            candidates_fetched = selection_results.get("number_of_candidates_returned_from_opensearch", 0)
            filtered_out = selection_results.get("number_filtered_out_by_postgres", 0)
            eligible_count = len(selection_results.get("eligible_candidates", []))
            logger.info(
                f"CORRECTED SELECTION stats: {candidates_fetched} fetched, {filtered_out} filtered out, {eligible_count} eligible"
            )

            exclusion_counts = selection_results.get("exclusion_counts", {})
            if exclusion_counts:
                logger.info(f"Exclusion counts: {exclusion_counts}")

            selected_cve = selection_results.get("selected_cve")
            if (
                selected_cve
                and selected_cve not in self.session_processed_cves
                and not self._has_terminal_success(selected_cve)
            ):
                return {
                    "cve_id": selected_cve,
                    "selection_data": selection_results,
                    "selection_timestamp": time.time(),
                }

            for cve_id in self._normalize_candidate_ids(selection_results):
                if cve_id in self.session_processed_cves:
                    logger.info(f"Skipping {cve_id}: already processed in current session")
                    continue
                if self._has_terminal_success(cve_id):
                    logger.info(f"Skipping {cve_id}: terminal success already exists")
                    continue
                logger.info(f"Fallback-selected CVE after local guards: {cve_id}")
                selection_results["selected_cve"] = cve_id
                return {
                    "cve_id": cve_id,
                    "selection_data": selection_results,
                    "selection_timestamp": time.time(),
                }

            logger.info(f"No eligible CVE found from {candidates_fetched} candidates after local guards")
            return None

        except Exception as e:
            logger.error(f"Failed to select CVE with corrected selector: {e}")
            return None

    def _run_phase1_pipeline(self, cve_id: str, run_id: str) -> Dict[str, Any]:
        start_time = get_utc_now()
        run_results = {
            "run_id": run_id,
            "cve_id": cve_id,
            "status": ExecutionStatus.FAILED.value,
            "context_snapshot_id": None,
            "generation_run_id": None,
            "qa_result": None,
            "qa_score": None,
            "errors": [],
            "start_time": datetime_to_iso(start_time),
        }

        try:
            runner = Phase1DirectCVERunner(cve_id)
            results = runner.run_pipeline()

            run_results["context_snapshot_id"] = results.get("context_snapshot_id")
            run_results["generation_run_id"] = results.get("generation_run_id")
            run_results["qa_result"] = results.get("qa_result")
            run_results["qa_score"] = results.get("qa_score")
            run_results["errors"] = results.get("errors", [])
            stage_timings = results.get("stage_timings", {})
            run_results["stage_timings"] = stage_timings

            execution_status = results.get("execution_status", "failed")
            pipeline_status = results.get("pipeline_status", "failed")

            if execution_status == "completed":
                run_results["status"] = ExecutionStatus.COMPLETED.value
            else:
                run_results["status"] = ExecutionStatus.FAILED.value

            run_results["pipeline_status"] = pipeline_status

        except Exception as e:
            error_msg = f"Pipeline execution failed: {e}"
            logger.error(error_msg)
            run_results["errors"].append(error_msg)
            run_results["status"] = ExecutionStatus.FAILED.value

        end_time = get_utc_now()
        run_results["end_time"] = datetime_to_iso(end_time)
        run_results["duration_seconds"] = calculate_duration_seconds(start_time, end_time)
        return run_results

    def _process_single_cve(self, cve_selection: Dict[str, Any]) -> bool:
        cve_id = cve_selection["cve_id"]
        run_id = self._generate_run_id()

        logger.info(f"Starting run {self.run_counter} for CVE {cve_id}")
        logger.info(f"Run ID: {run_id}")
        logger.info(f"Timeout set to {self.timeout_minutes} minutes")

        stage_timings = {}
        total_start_time = time.time()

        selection_start_time = cve_selection.get("selection_timestamp", total_start_time)
        stage_timings["selection_time_seconds"] = total_start_time - selection_start_time

        lock_start_time = time.time()
        if not self.lock_manager.acquire_lock(self.session_id, run_id, cve_id):
            logger.error(f"Failed to acquire lock for CVE {cve_id} - skipping")
            return False
        stage_timings["lock_acquire_time_seconds"] = time.time() - lock_start_time

        run_record_start_time = time.time()
        self.records_manager.start_run(self.session_id, run_id, self.run_counter, cve_id)
        stage_timings["run_record_start_time_seconds"] = time.time() - run_record_start_time

        run_results = None
        timeout_occurred = False
        start_time = time.time()

        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._run_phase1_pipeline, cve_id, run_id)

                try:
                    run_results = future.result(timeout=self.timeout_minutes * 60)
                    logger.info(f"Pipeline completed within timeout ({self.timeout_minutes} minutes)")
                except FutureTimeoutError:
                    timeout_occurred = True
                    elapsed_time = time.time() - start_time
                    logger.error(f"Pipeline timeout after {elapsed_time:.2f} seconds ({self.timeout_minutes} minute limit)")
                    future.cancel()

                    run_results = {
                        "run_id": run_id,
                        "cve_id": cve_id,
                        "status": ExecutionStatus.FAILED.value,
                        "context_snapshot_id": None,
                        "generation_run_id": None,
                        "qa_result": None,
                        "qa_score": None,
                        "errors": [f"Pipeline timeout after {elapsed_time:.2f} seconds (>{self.timeout_minutes} minutes)"],
                        "pipeline_status": "timeout_failure",
                        "start_time": datetime_to_iso(get_utc_now()),
                        "end_time": datetime_to_iso(get_utc_now()),
                        "duration_seconds": elapsed_time,
                    }
                except Exception as e:
                    logger.error(f"Pipeline execution error: {e}")
                    raise

            completion_status = ExecutionStatus(run_results["status"])

            if timeout_occurred:
                completion_status = ExecutionStatus.FAILED
                run_results["status"] = ExecutionStatus.FAILED.value
                metadata = {
                    "selection_data": cve_selection.get("selection_data", {}),
                    "run_mode": self.mode.value,
                    "pipeline_status": "timeout_failure",
                    "timeout_minutes": self.timeout_minutes,
                    "elapsed_seconds": time.time() - start_time,
                    "timeout_classification": "execution_timeout",
                    "stage_timings": stage_timings,
                }
            else:
                metadata = {
                    "selection_data": cve_selection.get("selection_data", {}),
                    "run_mode": self.mode.value,
                    "pipeline_status": run_results.get("pipeline_status", "unknown"),
                    "stage_timings": stage_timings,
                }

            if not timeout_occurred and "stage_timings" in run_results:
                metadata["stage_timings"] = run_results["stage_timings"]

            db_persist_start_time = time.time()
            self.records_manager.complete_run(
                session_id=self.session_id,
                run_id=run_id,
                cve_id=cve_id,
                status=completion_status,
                context_snapshot_id=run_results.get("context_snapshot_id"),
                generation_run_id=run_results.get("generation_run_id"),
                qa_result=run_results.get("qa_result"),
                qa_score=run_results.get("qa_score"),
                errors=run_results.get("errors", []),
                metadata=metadata,
            )
            stage_timings["db_persist_time_seconds"] = time.time() - db_persist_start_time

            pipeline_status = run_results.get("pipeline_status", "failed")
            execution_status = run_results.get("status", ExecutionStatus.FAILED.value)
            success = execution_status == ExecutionStatus.COMPLETED.value and pipeline_status == "success"

            if success:
                logger.info(f"Run {self.run_counter} completed successfully for CVE {cve_id}")
                logger.info(f"Pipeline status: {pipeline_status}")
            elif timeout_occurred:
                logger.error(f"Run {self.run_counter} TIMEOUT for CVE {cve_id} after {self.timeout_minutes} minutes")
                logger.error("Timeout classification: execution_timeout")
            elif execution_status == ExecutionStatus.COMPLETED.value:
                logger.warning(f"Run {self.run_counter} completed with pipeline status: {pipeline_status} for CVE {cve_id}")
                if run_results.get("errors"):
                    logger.warning(f"Pipeline errors: {run_results['errors']}")
            else:
                logger.error(f"Run {self.run_counter} failed for CVE {cve_id}")
                logger.error(f"Execution status: {execution_status}, Pipeline status: {pipeline_status}")
                if run_results.get("errors"):
                    logger.error(f"Errors: {run_results['errors']}")

            lock_release_start_time = time.time()
            lock_status = completion_status
            self.lock_manager.release_lock(self.session_id, run_id, lock_status)
            stage_timings["lock_release_time_seconds"] = time.time() - lock_release_start_time

            stage_timings["total_run_time_seconds"] = time.time() - total_start_time

            logger.info("Stage timing breakdown:")
            for stage_name, stage_time in stage_timings.items():
                logger.info(f"  {stage_name}: {stage_time:.2f} seconds")

            self._save_run_metadata(run_id, stage_timings, metadata)
            return success

        except Exception as e:
            logger.error(f"Unexpected error processing CVE {cve_id}: {e}")

            stage_timings["total_run_time_seconds"] = time.time() - total_start_time

            exception_metadata = {
                "selection_data": cve_selection.get("selection_data", {}),
                "run_mode": self.mode.value,
                "error_type": "unexpected_exception",
                "exception_message": str(e),
                "stage_timings": stage_timings,
            }

            self.records_manager.complete_run(
                session_id=self.session_id,
                run_id=run_id,
                cve_id=cve_id,
                status=ExecutionStatus.FAILED,
                errors=[str(e)],
                metadata=exception_metadata,
            )

            self._save_run_metadata(run_id, stage_timings, exception_metadata)
            self.lock_manager.release_lock(self.session_id, run_id, ExecutionStatus.FAILED)
            return False

    def _check_stop_conditions(self) -> bool:
        if self.should_stop:
            logger.info("Stop signal received")
            return True
        if self.max_runs > 0 and self.run_counter >= self.max_runs:
            logger.info(f"Reached maximum runs limit: {self.max_runs}")
            return True
        return False

    def _wait_between_runs(self, wait_seconds: int = 5):
        logger.info(f"Waiting {wait_seconds} seconds before next run...")
        for _ in range(wait_seconds * 10):
            if self.should_stop:
                break
            time.sleep(0.1)

    def _save_run_metadata(self, run_id: str, stage_timings: Dict[str, float], metadata: Dict[str, Any]) -> None:
        try:
            run_dir = Path("logs") / "runs" / run_id
            run_dir.mkdir(parents=True, exist_ok=True)

            metadata_with_timings = {
                "run_id": run_id,
                "session_id": self.session_id,
                "captured_at": datetime_to_iso(get_utc_now()),
                "stage_timings": stage_timings,
                "metadata": metadata,
            }

            file_path = run_dir / "metadata.json"
            with open(file_path, "w") as f:
                json.dump(metadata_with_timings, f, indent=2, default=str)

            logger.info(f"Saved run metadata to file: {file_path}")
        except Exception as e:
            logger.error(f"Failed to save run metadata to file: {e}")

    def run_single(self) -> bool:
        logger.info("Running in SINGLE_RUN mode")
        cve_selection = self._select_fresh_cve_phase1()
        if not cve_selection:
            logger.error("No CVE selected for processing")
            return False

        success = self._process_single_cve(cve_selection)
        self.session_processed_cves.add(cve_selection["cve_id"])
        return success

    def run_continuous(self) -> int:
        logger.info("Running in CONTINUOUS mode")
        processed_count = 0

        while not self._check_stop_conditions():
            logger.info(f"=== Continuous Run #{self.run_counter + 1} ===")

            cve_selection = self._select_fresh_cve_phase1()
            if not cve_selection:
                logger.warning("No CVE selected - waiting before retry")
                self._wait_between_runs(30)
                continue

            success = self._process_single_cve(cve_selection)
            if success:
                processed_count += 1

            if not self._check_stop_conditions():
                self._wait_between_runs(self.wait_seconds)

        logger.info(f"Continuous processing stopped. Processed {processed_count} CVEs")
        return processed_count

    def run_drain_queue(self, batch_size: int = 10) -> int:
        logger.info(f"Running in DRAIN_QUEUE mode (batch size: {batch_size})")
        processed_count = 0
        batch_processed = 0

        while not self._check_stop_conditions() and batch_processed < batch_size:
            logger.info(f"=== Queue Drain Run #{self.run_counter + 1} (Batch: {batch_processed + 1}/{batch_size}) ===")

            cve_selection = self._select_fresh_cve_phase1()
            if not cve_selection:
                logger.info("No more eligible CVEs in queue")
                break

            success = self._process_single_cve(cve_selection)
            self.session_processed_cves.add(cve_selection["cve_id"])
            if success:
                processed_count += 1
                batch_processed += 1
            else:
                batch_processed += 1

            if not self._check_stop_conditions() and batch_processed < batch_size:
                self._wait_between_runs(self.wait_seconds)

        logger.info(f"Queue drain completed. Processed {processed_count} CVEs")
        return processed_count

    def generate_session_report(self) -> Dict[str, Any]:
        logger.info("Generating session report...")
        session_summary = self.records_manager.get_session_summary(self.session_id)

        return {
            "session_id": self.session_id,
            "mode": self.mode.value,
            "total_runs": self.run_counter,
            "session_start_time": datetime_to_iso(self.session_start_time),
            "summary": session_summary.get("summary", {}),
            "processed_cves": session_summary.get("processed_cves", []),
            "report_generated_at": datetime_to_iso(get_utc_now()),
        }

    def dump_run_records(self, output_file: Optional[str] = None):
        try:
            records_sql = """
            SELECT * FROM continuous_run_records 
            WHERE session_id = %s 
            ORDER BY run_number
            """
            records = self.db.fetch_all(records_sql, (self.session_id,))

            if not records:
                logger.warning("No run records found for session")
                return

            output = {
                "session_id": self.session_id,
                "dump_timestamp": datetime_to_iso(get_utc_now()),
                "total_records": len(records),
                "records": records,
            }

            if not output_file:
                timestamp = get_utc_now().strftime("%Y%m%d_%H%M%S")
                output_file = f"logs/sessions/{self.session_id}/run_records_{timestamp}.json"

            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w") as f:
                json.dump(output, f, indent=2, default=str)

            logger.info(f"Run records dumped to {output_file}")
        except Exception as e:
            logger.error(f"Failed to dump run records: {e}")

    def run(self) -> Tuple[bool, Dict[str, Any]]:
        logger.info("=" * 80)
        logger.info("PHASE 1 CONTINUOUS EXECUTION SYSTEM")
        logger.info("=" * 80)

        session_start_time = get_utc_now()

        try:
            if self.mode == RunMode.SINGLE_RUN:
                success = self.run_single()
                processed_count = 1 if success else 0
            elif self.mode == RunMode.CONTINUOUS:
                processed_count = self.run_continuous()
                success = processed_count > 0
            elif self.mode == RunMode.DRAIN_QUEUE:
                processed_count = self.run_drain_queue(self.batch_size)
                success = processed_count > 0
            else:
                logger.error(f"Unknown mode: {self.mode}")
                return False, {}

            session_report = self.generate_session_report()
            self.dump_run_records()

            session_end_time = get_utc_now()
            duration = calculate_duration_seconds(session_start_time, session_end_time)

            logger.info("=" * 80)
            logger.info("SESSION COMPLETE")
            logger.info(f"Session ID: {self.session_id}")
            logger.info(f"Mode: {self.mode.value}")
            logger.info(f"Total runs attempted: {self.run_counter}")
            logger.info(f"Successfully processed: {processed_count}")
            logger.info(f"Session duration: {duration:.2f} seconds")
            logger.info(f"Average time per run: {duration / max(self.run_counter, 1):.2f} seconds")
            logger.info("=" * 80)

            print("\nSESSION SUMMARY:")
            summary = session_report.get("summary", {})

            total_runs = summary.get("total_runs") or 0
            completed_runs = summary.get("completed_runs") or 0
            failed_runs = summary.get("failed_runs") or 0
            total_duration = summary.get("total_duration") or 0.0
            avg_duration = summary.get("avg_duration") or 0.0

            print(f"  Total runs: {total_runs}")
            print(f"  Completed: {completed_runs}")
            print(f"  Failed: {failed_runs}")
            print(f"  Session duration: {total_duration:.2f} seconds")
            print(f"  Average run time: {avg_duration:.2f} seconds")

            return success, session_report

        except Exception as e:
            logger.error(f"Execution failed: {e}")
            import traceback
            traceback.print_exc()
            return False, {}


def main():
    parser = argparse.ArgumentParser(description="Phase 1 Continuous Execution System with Parallel Safety")

    parser.add_argument(
        "--mode",
        type=str,
        choices=["single", "continuous", "drain"],
        default="single",
        help="Execution mode: single (one CVE), continuous (until stopped), drain (process batch)",
    )
    parser.add_argument(
        "--max-runs",
        type=int,
        default=0,
        help="Maximum number of runs (0 = unlimited, only for continuous mode)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Batch size for drain mode (default: 10)",
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=0,
        help="Seconds to wait between runs (default: 5)",
    )
    parser.add_argument(
        "--timeout-minutes",
        type=int,
        default=30,
        help="Maximum execution time per CVE run in minutes (default: 30)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output session report as JSON only",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    mode_map = {
        "single": RunMode.SINGLE_RUN,
        "continuous": RunMode.CONTINUOUS,
        "drain": RunMode.DRAIN_QUEUE,
    }

    system = Phase1ContinuousExecutionSystem(
        mode=mode_map[args.mode],
        max_runs=args.max_runs,
        timeout_minutes=args.timeout_minutes,
        batch_size=args.batch_size,
        wait_seconds=args.wait_seconds,
    )

    success, session_report = system.run()

    if args.json:
        print(json.dumps(session_report, indent=2, default=str))
    else:
        if success:
            print("\nContinuous execution completed successfully")
            print(f"Session ID: {system.session_id}")
        else:
            print("\nContinuous execution completed with failures")
            print(f"Session ID: {system.session_id}")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()