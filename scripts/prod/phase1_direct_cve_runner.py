from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Phase1DirectCVERunner:
    def __init__(self, cve_id: str):
        self.cve_id = cve_id
        self.scripts_dir = Path(__file__).resolve().parent
        logger.info("Phase1DirectCVERunner initialized for %s", self.cve_id)

    def _extract_last_json_object(self, text: str) -> Optional[Dict[str, Any]]:
        if not text:
            return None

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        for i in range(len(lines) - 1, -1, -1):
            candidate = "\n".join(lines[i:])
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                continue

        start_positions = [idx for idx, ch in enumerate(text) if ch == "{"]
        for start in reversed(start_positions):
            candidate = text[start:].strip()
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                continue

        return None

    def _run_subprocess_json(
        self,
        cmd: list[str],
        step_name: str,
        require_json: bool = False,
    ) -> Dict[str, Any]:
        logger.info("Running %s: %s", step_name, " ".join(cmd))
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(self.scripts_dir.parent.parent),
        )

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        if stderr.strip():
            logger.warning("%s stderr:\n%s", step_name, stderr[:10000])

        parsed = self._extract_last_json_object(stdout)

        if proc.returncode != 0:
            raise RuntimeError(
                f"{step_name} failed with return code {proc.returncode}. "
                f"stderr={stderr[:2000]!r} stdout={stdout[:2000]!r}"
            )

        if parsed is None and require_json:
            raise RuntimeError(
                f"{step_name} did not emit a parseable JSON object. "
                f"stdout={stdout[:2000]!r}"
            )

        return parsed or {}

    def run_pipeline(self) -> Dict[str, Any]:
        start_time = time.time()
        stage_timings: Dict[str, float] = {}
        context_snapshot_id = None
        generation_run_id = None
        generation_status = "failed"
        qa_result = None
        qa_score = None
        qa_feedback = None
        pipeline_status = "failed"
        execution_status = "failed"
        errors: list[str] = []

        try:
            logger.info("PHASE 1 DIRECT CVE PIPELINE FOR %s", self.cve_id)
            logger.info("============================================================")

            context_start = time.time()
            context_cmd = [
                sys.executable,
                "-m",
                "scripts.prod.02_85_build_context_snapshot_v0_1_0",
                "--cve",
                self.cve_id,
            ]
            context_result = self._run_subprocess_json(
                context_cmd,
                "context snapshot build",
                require_json=False,
            )
            context_snapshot_id = context_result.get("context_snapshot_id") or context_result.get("id")
            stage_timings["context_snapshot_time_seconds"] = round(time.time() - context_start, 2)
            logger.info("Context snapshot created: ID %s", context_snapshot_id)

            generation_start = time.time()
            generation_cmd = [
                sys.executable,
                "-m",
                "scripts.prod.03_01_run_playbook_generation_v0_1_1_real_retrieval",
                "--cve",
                self.cve_id,
            ]
            generation_result = self._run_subprocess_json(
                generation_cmd,
                "generation",
                require_json=True,
            )

            generation_run_id = generation_result.get("generation_run_id")
            generation_status = generation_result.get("status", "failed")
            qa_result = generation_result.get("qa_result")
            qa_score = generation_result.get("qa_score")
            qa_feedback = generation_result.get("error")
            stage_timings["generation_total_time_seconds"] = round(time.time() - generation_start, 2)

            execution_status = "completed"
            pipeline_status = "success" if generation_status == "completed" else "failed"

        except Exception as exc:
            error_message = f"Pipeline execution failed: {exc}"
            logger.error(error_message)
            errors.append(error_message)
            execution_status = "failed"
            pipeline_status = "failed"

        return {
            "cve_id": self.cve_id,
            "context_snapshot_id": context_snapshot_id,
            "generation_run_id": generation_run_id,
            "generation_status": generation_status,
            "qa_result": qa_result,
            "qa_score": qa_score,
            "qa_feedback": qa_feedback,
            "pipeline_status": pipeline_status,
            "execution_status": execution_status,
            "errors": errors,
            "duration_seconds": round(time.time() - start_time, 2),
            "stage_timings": stage_timings,
        }


def main():
    parser = argparse.ArgumentParser(description="Phase 1 direct CVE runner")
    parser.add_argument("--cve-id", required=True)
    args = parser.parse_args()

    runner = Phase1DirectCVERunner(args.cve_id)
    result = runner.run_pipeline()
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()