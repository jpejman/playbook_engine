"""
Multi-model evaluation framework for continuous pipeline v0.3.1
Version: v0.3.1
Purpose:
- Reuse v0.3.0 evaluation flow
- Add structured-output normalization / graded validation path from v0.3.1
- Keep console visibility for debugging
- Use existing setup_logging() contract without unsupported keyword args
"""

from __future__ import annotations

import sys
import os
import argparse
import logging
import uuid
import time
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

# Add repo root to sys.path
sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            )
        )
    )
)

from scripts.prod.continuous_pipeline_v0_3_1.log_setup import setup_logging
from scripts.prod.continuous_pipeline_v0_3_1.evaluation_selector import EvaluationSelector
from scripts.prod.continuous_pipeline_v0_3_1.evaluation_runner import EvaluationRunner
from scripts.prod.continuous_pipeline_v0_3_1.evaluation_summary import EvaluationSummary

logger = logging.getLogger(__name__)


@dataclass
class EvaluationConfig:
    models: List[str]
    cve_source: str  # queue | opensearch | list | file
    cve_list: Optional[List[str]] = None
    cve_file: Optional[str] = None
    limit: Optional[int] = None
    batch_size: Optional[int] = None
    evaluation_label: Optional[str] = None
    execution_mode: str = "sequential"
    max_workers: Optional[int] = None
    force: bool = False
    timeout: int = 300
    fail_fast: bool = False


class ModelEvaluator:
    def __init__(self, config: EvaluationConfig):
        self.config = config
        self.evaluation_batch_id = str(uuid.uuid4())

        self.selector = EvaluationSelector()
        self.runner = EvaluationRunner(
            evaluation_batch_id=self.evaluation_batch_id,
            evaluation_label=config.evaluation_label,
            execution_mode=config.execution_mode,
            max_workers=config.max_workers,
            timeout=config.timeout,
            fail_fast=config.fail_fast,
        )
        self.summary = EvaluationSummary()

        logger.info("Initialized ModelEvaluator")
        logger.info("Evaluation batch ID: %s", self.evaluation_batch_id)
        logger.info("Models to evaluate: %s", config.models)
        logger.info("CVE source: %s", config.cve_source)
        logger.info("Execution mode: %s", config.execution_mode)

    def run(self) -> bool:
        start_time = time.time()

        try:
            print(">>> selecting CVEs for evaluation...", flush=True)
            logger.info("Selecting CVEs for evaluation...")

            cves = self._select_cves()
            if not cves:
                print(">>> no CVEs selected; exiting", flush=True)
                logger.error("No CVEs selected for evaluation")
                return False

            print(f">>> selected {len(cves)} CVE(s): {cves}", flush=True)
            logger.info("Selected %d CVEs for evaluation", len(cves))

            print(f">>> running models: {self.config.models}", flush=True)
            logger.info("Starting evaluation runs...")

            results = self.runner.run_evaluation(
                cves=cves,
                models=self.config.models,
                force=self.config.force,
            )

            print(">>> generating summary...", flush=True)
            logger.info("Generating evaluation summary...")

            self.summary.generate_summary(
                results=results,
                evaluation_batch_id=self.evaluation_batch_id,
                evaluation_label=self.config.evaluation_label,
                models=self.config.models,
                cves=cves,
            )

            elapsed_time = time.time() - start_time
            self._print_final_summary(results, elapsed_time)
            return True

        except Exception as e:
            print(f">>> evaluation failed: {e}", flush=True)
            logger.error("Evaluation failed: %s", e, exc_info=True)
            return False

    def _select_cves(self) -> List[str]:
        print(f">>> _select_cves source={self.config.cve_source}", flush=True)

        if self.config.cve_source == "queue":
            selected = self.selector.select_from_queue(
                limit=self.config.limit or self.config.batch_size
            )
            print(f">>> queue selected: {selected}", flush=True)
            return selected

        if self.config.cve_source == "opensearch":
            selected = self.selector.select_from_opensearch(
                limit=self.config.limit or self.config.batch_size
            )
            print(f">>> opensearch selected: {selected}", flush=True)
            return selected

        if self.config.cve_source == "list":
            selected = self.config.cve_list or []
            print(f">>> explicit list selected: {selected}", flush=True)
            return selected

        if self.config.cve_source == "file":
            selected = self.selector.select_from_file(self.config.cve_file)
            print(f">>> file selected: {selected}", flush=True)
            return selected

        raise ValueError(f"Unknown CVE source: {self.config.cve_source}")

    def _print_final_summary(self, results: Dict[str, Any], elapsed_time: float) -> None:
        print("\n" + "=" * 80, flush=True)
        print("EVALUATION COMPLETE", flush=True)
        print("=" * 80, flush=True)
        print(f"Evaluation Batch ID: {self.evaluation_batch_id}", flush=True)
        if self.config.evaluation_label:
            print(f"Evaluation Label: {self.config.evaluation_label}", flush=True)
        print(f"Total CVEs: {len(results.get('cves', []))}", flush=True)
        print(f"Total Models: {len(self.config.models)}", flush=True)
        print(f"Total Runs Attempted: {results.get('total_attempted', 0)}", flush=True)
        print(f"Completed: {results.get('completed', 0)}", flush=True)
        print(f"Failed: {results.get('failed', 0)}", flush=True)
        print(f"Elapsed Time: {elapsed_time:.2f} seconds", flush=True)

        model_stats = results.get("model_stats", {})
        if model_stats:
            print("\nModel Statistics:", flush=True)
            for model, stats in model_stats.items():
                print(f"  {model}:", flush=True)
                print(f"    Completed: {stats.get('completed', 0)}", flush=True)
                print(f"    Failed: {stats.get('failed', 0)}", flush=True)
                avg_duration = float(stats.get("avg_duration", 0.0) or 0.0)
                print(f"    Avg Duration: {avg_duration:.2f}s", flush=True)

        print("\nQuery results with:", flush=True)
        print(
            f"SELECT * FROM public.generation_runs "
            f"WHERE evaluation_batch_id = '{self.evaluation_batch_id}' "
            f"ORDER BY created_at DESC;",
            flush=True,
        )
        print("=" * 80, flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Multi-model evaluation framework for continuous pipeline v0.3.1"
    )

    model_group = parser.add_mutually_exclusive_group(required=True)
    model_group.add_argument(
        "--models",
        type=str,
        help='Comma-separated model list, e.g. "gemma3:4b,qwen3.5:4b"',
    )
    model_group.add_argument(
        "--models-file",
        type=str,
        help="File containing one model per line",
    )

    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--source",
        choices=["queue", "opensearch"],
        help="CVE source",
    )
    source_group.add_argument(
        "--cve-list",
        type=str,
        help='Comma-separated CVE list, e.g. "CVE-2023-4863,CVE-2021-44228"',
    )
    source_group.add_argument(
        "--cve-file",
        type=str,
        help="File containing one CVE per line",
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=1,
        help="Number of CVEs to process",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Optional CVE limit override",
    )
    parser.add_argument(
        "--eval-label",
        type=str,
        help="Evaluation label",
    )
    parser.add_argument(
        "--execution",
        choices=["sequential", "parallel"],
        default="sequential",
        help="Execution mode",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        help="Parallel worker count",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force evaluation even if already processed in this evaluation context",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout per run in seconds",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop after first failed run",
    )

    # Kept for compatibility if Kilo added it elsewhere; ignored by logging init
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        help="Optional log level (currently informational only)",
    )

    return parser.parse_args()


def load_models_from_args(args: argparse.Namespace) -> List[str]:
    if args.models:
        models = [m.strip() for m in args.models.split(",") if m.strip()]
        if not models:
            raise ValueError("Parsed empty model list from --models")
        return models

    if args.models_file:
        with open(args.models_file, "r", encoding="utf-8") as f:
            models = [line.strip() for line in f if line.strip()]
        if not models:
            raise ValueError("Parsed empty model list from --models-file")
        return models

    raise ValueError("No models specified")


def determine_cve_source(args: argparse.Namespace) -> tuple[str, Optional[List[str]], Optional[str]]:
    if args.source:
        return args.source, None, None

    if args.cve_list:
        cves = [cve.strip() for cve in args.cve_list.split(",") if cve.strip()]
        return "list", cves, None

    if args.cve_file:
        return "file", None, args.cve_file

    raise ValueError("No CVE source specified")


def main() -> None:
    print(">>> evaluate_models_v0_3_1 main() started", flush=True)

    args = parse_args()
    print(f">>> args parsed: {args}", flush=True)

    # IMPORTANT: use existing setup_logging() contract, no unsupported kwargs
    setup_logging()

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Ensure console output exists even if setup_logging writes only to file
    if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        root_logger.addHandler(console_handler)

    global logger
    logger = logging.getLogger(__name__)

    print(">>> logging initialized", flush=True)
    logger.info("evaluate_models_v0_3_1 starting")

    models = load_models_from_args(args)
    print(f">>> models loaded: {models}", flush=True)

    cve_source, cve_list, cve_file = determine_cve_source(args)
    print(
        f">>> cve source resolved: source={cve_source}, cve_list={cve_list}, cve_file={cve_file}",
        flush=True,
    )

    config = EvaluationConfig(
        models=models,
        cve_source=cve_source,
        cve_list=cve_list,
        cve_file=cve_file,
        limit=args.limit,
        batch_size=args.batch_size,
        evaluation_label=args.eval_label,
        execution_mode=args.execution,
        max_workers=args.max_workers,
        force=args.force,
        timeout=args.timeout,
        fail_fast=args.fail_fast,
    )

    print(">>> evaluation config created", flush=True)

    evaluator = ModelEvaluator(config)
    print(">>> evaluator initialized", flush=True)

    success = evaluator.run()
    print(f">>> evaluator.run() returned: {success}", flush=True)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()