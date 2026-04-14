#!/usr/bin/env python3
"""
VS.ai — Playbook Engine Gen-3
Phase 1 Direct CVE Runner - No Selection
Version: v1.0.0
Timestamp (UTC): 2026-04-10

Purpose:
- Run Phase 1 pipeline for a SPECIFIC CVE (no selection)
- Accepts CVE ID as parameter
- Runs context snapshot → generation → QA
- Returns detailed pipeline results
- Proper success/failure tracking
"""

import sys
import json
import subprocess
import argparse
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.utils.db import DatabaseClient
from scripts.prod.time_utils import get_utc_now, datetime_to_iso, calculate_duration_seconds

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PipelineStatus:
    """Pipeline status tracking with detailed semantics."""
    
    @staticmethod
    def determine_pipeline_status(
        generation_status: Optional[str],
        qa_result: Optional[str],
        has_generation_run_id: bool,
        has_qa_result: bool
    ) -> Tuple[str, str]:
        """
        Determine execution and pipeline status based on pipeline outcomes.
        
        Returns:
            Tuple of (execution_status, pipeline_status)
            execution_status: 'completed' | 'failed' (did the pipeline run to completion?)
            pipeline_status: 'success' | 'failed' | 'partial' (what was the outcome?)
        """
        # Execution status: did the pipeline complete (run all steps)?
        # We consider it completed if we attempted all steps, regardless of success
        execution_status = 'completed'
        
        # Pipeline status: what was the outcome?
        if generation_status == 'completed' and qa_result == 'approved':
            pipeline_status = 'success'
        elif generation_status == 'failed' or not has_generation_run_id:
            # Generation failed or didn't produce a run ID
            pipeline_status = 'failed'
        elif not has_qa_result or qa_result not in ['approved', 'rejected']:
            # QA didn't run or produced invalid result
            pipeline_status = 'partial'
        elif qa_result == 'rejected':
            # Generation succeeded but QA rejected
            pipeline_status = 'partial'
        else:
            # Unknown state
            pipeline_status = 'failed'
            
        return execution_status, pipeline_status


class Phase1DirectCVERunner:
    """Phase 1 runner for specific CVE (no selection)."""
    
    def __init__(self, cve_id: str):
        if not cve_id:
            raise ValueError("CVE ID must be explicitly provided")
        
        self.cve_id = cve_id
        self.db = DatabaseClient()
        
        # Pipeline results
        self.results = {
            "timestamp_utc": datetime_to_iso(get_utc_now()),
            "cve_id": cve_id,
            "execution_status": "not_started",
            "pipeline_status": "unknown",
            "context_snapshot_id": None,
            "generation_run_id": None,
            "generation_status": None,
            "qa_result": None,
            "qa_score": None,
            "errors": [],
            "pipeline_complete": False,
            "start_time": None,
            "end_time": None,
            "duration_seconds": None
        }
        
        logger.info(f"Phase1DirectCVERunner initialized for {self.cve_id}")
    
    def run_context_snapshot(self) -> Optional[int]:
        """Run context snapshot builder for the specific CVE."""
        logger.info(f"Step 1: Building context snapshot for {self.cve_id}...")
        
        try:
            # Run the context snapshot script
            cmd = [
                sys.executable, 
                "scripts/prod/02_85_build_context_snapshot_v0_1_0.py",
                "--cve", self.cve_id,
                "--json"
            ]
            
            cwd_path = Path(__file__).parent.parent.parent.resolve()
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=cwd_path
            )
            
            if result.returncode != 0:
                error_msg = f"Context snapshot failed: {result.stderr}"
                logger.error(error_msg)
                self.results['errors'].append(error_msg)
                return None
            
            # Parse JSON output
            output_data = json.loads(result.stdout)
            context_snapshot_id = output_data.get('context_snapshot_id')
            
            if context_snapshot_id:
                self.results['context_snapshot_id'] = context_snapshot_id
                logger.info(f"Context snapshot created: ID {context_snapshot_id}")
                return context_snapshot_id
            else:
                error_msg = f"No context snapshot ID returned: {output_data}"
                logger.error(error_msg)
                self.results['errors'].append(error_msg)
                return None
                
        except Exception as e:
            error_msg = f"Context snapshot execution failed: {e}"
            logger.error(error_msg)
            self.results['errors'].append(error_msg)
            return None
    
    def run_generation(self) -> Tuple[Optional[str], Optional[str]]:
        """Run playbook generation for the specific CVE."""
        logger.info(f"Step 2: Running playbook generation for {self.cve_id}...")
        
        try:
            # Run the generation script
            cmd = [
                sys.executable,
                "scripts/prod/03_01_run_playbook_generation_v0_1_1_real_retrieval.py",
                "--cve", self.cve_id
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent.parent
            )
            
            # Parse the output to find key information
            generation_run_id = None
            generation_status = "unknown"
            generation_timings = {}
            
            # Combine stdout and stderr for parsing
            combined_output = result.stdout + "\n" + result.stderr
            output_lines = combined_output.split('\n')
            
            # Parse for generation timings
            timing_patterns = {
                'generation_pre_ollama_time_seconds': 'generation_pre_ollama_time_seconds:',
                'generation_ollama_roundtrip_time_seconds': 'generation_ollama_roundtrip_time_seconds:',
                'generation_post_response_time_seconds': 'generation_post_response_time_seconds:',
                'generation_gpu_active_time_seconds': 'generation_gpu_active_time_seconds:',
                'generation_non_gpu_time_seconds': 'generation_non_gpu_time_seconds:',
                'evidence_collection_time_seconds': 'evidence_collection_time_seconds:',
                'opensearch_retrieval_time_seconds': 'opensearch_retrieval_time_seconds:',
                'postgres_retrieval_time_seconds': 'postgres_retrieval_time_seconds:',
                'prompt_input_builder_time_seconds': 'prompt_input_builder_time_seconds:',
                'prompt_template_load_time_seconds': 'prompt_template_load_time_seconds:',
                'llm_call_total_time_seconds': 'llm_call_total_time_seconds:',
                'parser_transform_time_seconds': 'parser_transform_time_seconds:',
                'generation_db_write_time_seconds': 'generation_db_write_time_seconds:',
                'post_generation_cleanup_time_seconds': 'post_generation_cleanup_time_seconds:',
                'full_generation_script_wall_clock_time_seconds': 'full_generation_script_wall_clock_time_seconds:'
            }
            
            for line in output_lines:
                if "Generation Run ID:" in line:
                    parts = line.split("Generation Run ID:")
                    if len(parts) > 1:
                        generation_run_id = parts[1].strip()
                elif "Final generation status:" in line:
                    parts = line.split("Final generation status:")
                    if len(parts) > 1:
                        generation_status = parts[1].strip().lower()
                else:
                    # Parse generation timings
                    for timing_key, pattern in timing_patterns.items():
                        if pattern in line:
                            parts = line.split(pattern)
                            if len(parts) > 1:
                                try:
                                    timing_value = float(parts[1].strip().split()[0])
                                    generation_timings[timing_key] = timing_value
                                except (ValueError, IndexError):
                                    pass
            
            self.results['generation_run_id'] = generation_run_id
            self.results['generation_status'] = generation_status
            self.results['generation_timings'] = generation_timings
            
            if generation_run_id:
                logger.info(f"Generation run created: ID {generation_run_id}, status: {generation_status}")
                # Log generation timings if available
                if generation_timings:
                    logger.info("Generation timing breakdown from subprocess:")
                    for timing_name, timing_value in generation_timings.items():
                        logger.info(f"  {timing_name}: {timing_value:.2f} seconds")
            else:
                logger.warning(f"Generation may have failed: status={generation_status}")
            
            return generation_run_id, generation_status
            
        except Exception as e:
            error_msg = f"Generation execution failed: {e}"
            logger.error(error_msg)
            self.results['errors'].append(error_msg)
            self.results['generation_status'] = 'execution_failed'
            return None, 'execution_failed'
    
    def run_qa(self) -> Tuple[Optional[str], Optional[float]]:
        """Run QA enforcement for the specific CVE."""
        logger.info(f"Step 3: Running QA enforcement for {self.cve_id}...")
        
        try:
            # Run the QA script
            cmd = [
                sys.executable,
                "scripts/prod/06_08_qa_enforcement_gate_canonical_v0_2_0.py",
                "--cve", self.cve_id
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent.parent
            )
            
            # Parse the output to find key information
            qa_result = None
            qa_score = None
            
            # Parse the output
            output_lines = result.stdout.split('\n')
            for line in output_lines:
                if "QA Result:" in line:
                    parts = line.split("QA Result:")
                    if len(parts) > 1:
                        qa_result = parts[1].strip().lower()
                elif "QA Score:" in line:
                    parts = line.split("QA Score:")
                    if len(parts) > 1:
                        score_str = parts[1].strip()
                        try:
                            qa_score = float(score_str)
                        except ValueError:
                            qa_score = 0.0
            
            self.results['qa_result'] = qa_result
            self.results['qa_score'] = qa_score
            
            if qa_result:
                logger.info(f"QA result: {qa_result}, score: {qa_score}")
            else:
                logger.warning(f"QA may have failed: no result found in output")
            
            return qa_result, qa_score
            
        except Exception as e:
            error_msg = f"QA execution failed: {e}"
            logger.error(error_msg)
            self.results['errors'].append(error_msg)
            return None, None
    
    def check_approved_playbook(self) -> Optional[str]:
        """Check if CVE has an approved playbook."""
        try:
            approved_playbook = self.db.fetch_one(
                """
                SELECT ap.id
                FROM approved_playbooks ap
                JOIN generation_runs gr ON ap.generation_run_id = gr.id
                WHERE gr.cve_id = %s
                LIMIT 1
                """,
                (self.cve_id,)
            )
            
            if approved_playbook and approved_playbook.get('id'):
                approved_id = approved_playbook.get('id')
                logger.info(f"Found approved playbook ID: {approved_id}")
                return approved_id
            
            return None
            
        except Exception as e:
            logger.warning(f"Could not check approved playbook: {e}")
            return None
    
    def run_pipeline(self) -> Dict[str, Any]:
        """Run complete Phase 1 pipeline for the specific CVE."""
        logger.info(f"PHASE 1 DIRECT CVE PIPELINE FOR {self.cve_id}")
        logger.info("=" * 60)
        
        # Record start time
        start_time = get_utc_now()
        self.results['start_time'] = datetime_to_iso(start_time)
        
        # Initialize stage timings
        stage_timings = {}
        
        try:
            # Step 1: Build context snapshot
            context_snapshot_start = time.time()
            context_snapshot_id = self.run_context_snapshot()
            stage_timings['context_snapshot_time_seconds'] = time.time() - context_snapshot_start
            
            if not context_snapshot_id:
                self.results['execution_status'] = 'failed'
                self.results['pipeline_status'] = 'failed'
                self.results['pipeline_complete'] = False
                logger.error(f"Pipeline failed at context snapshot for {self.cve_id}")
                return self.results
            
            # Step 2: Run generation
            generation_start = time.time()
            generation_run_id, generation_status = self.run_generation()
            stage_timings['generation_total_time_seconds'] = time.time() - generation_start
            has_generation_run_id = generation_run_id is not None
            
            # Add detailed generation timings if available
            if 'generation_timings' in self.results and self.results['generation_timings']:
                stage_timings.update(self.results['generation_timings'])
            
            # Step 3: Run QA (always attempt, even if generation failed)
            qa_start = time.time()
            qa_result, qa_score = self.run_qa()
            stage_timings['qa_time_seconds'] = time.time() - qa_start
            has_qa_result = qa_result is not None
            
            # Step 4: Check for approved playbook (informational)
            self.check_approved_playbook()
            
            # Determine pipeline outcomes
            execution_status, pipeline_status = PipelineStatus.determine_pipeline_status(
                generation_status=generation_status,
                qa_result=qa_result,
                has_generation_run_id=has_generation_run_id,
                has_qa_result=has_qa_result
            )
            
            # Record end time and duration
            end_time = get_utc_now()
            self.results['end_time'] = datetime_to_iso(end_time)
            self.results['duration_seconds'] = calculate_duration_seconds(start_time, end_time)
            
            # Add stage timings to results
            self.results['stage_timings'] = stage_timings
            
            # Update results
            self.results['execution_status'] = execution_status
            self.results['pipeline_status'] = pipeline_status
            self.results['pipeline_complete'] = True
            
            logger.info(f"Pipeline completed for {self.cve_id}")
            logger.info(f"Execution status: {execution_status}")
            logger.info(f"Pipeline status: {pipeline_status}")
            logger.info(f"Generation status: {generation_status}")
            logger.info(f"QA result: {qa_result}")
            logger.info(f"Duration: {self.results['duration_seconds']:.2f} seconds")
            
            # Log stage timings
            logger.info("Stage timings:")
            for stage, timing in stage_timings.items():
                logger.info(f"  {stage}: {timing:.2f} seconds")
            
            return self.results
            
            # Step 2: Run generation
            generation_run_id, generation_status = self.run_generation()
            has_generation_run_id = generation_run_id is not None
            
            # Step 3: Run QA (always attempt, even if generation failed)
            qa_result, qa_score = self.run_qa()
            has_qa_result = qa_result is not None
            
            # Step 4: Check for approved playbook (informational)
            self.check_approved_playbook()
            
            # Determine pipeline outcomes
            execution_status, pipeline_status = PipelineStatus.determine_pipeline_status(
                generation_status=generation_status,
                qa_result=qa_result,
                has_generation_run_id=has_generation_run_id,
                has_qa_result=has_qa_result
            )
            
            # Record end time and duration
            end_time = get_utc_now()
            self.results['end_time'] = datetime_to_iso(end_time)
            self.results['duration_seconds'] = calculate_duration_seconds(start_time, end_time)
            
            # Update results
            self.results['execution_status'] = execution_status
            self.results['pipeline_status'] = pipeline_status
            self.results['pipeline_complete'] = True
            
            logger.info(f"Pipeline completed for {self.cve_id}")
            logger.info(f"Execution status: {execution_status}")
            logger.info(f"Pipeline status: {pipeline_status}")
            logger.info(f"Generation status: {generation_status}")
            logger.info(f"QA result: {qa_result}")
            logger.info(f"Duration: {self.results['duration_seconds']:.2f} seconds")
            
            return self.results
            
        except Exception as e:
            error_msg = f"Pipeline execution failed: {e}"
            logger.error(error_msg)
            self.results['errors'].append(error_msg)
            
            # Record end time
            end_time = get_utc_now()
            self.results['end_time'] = datetime_to_iso(end_time)
            if self.results['start_time']:
                start_dt = datetime.fromisoformat(self.results['start_time'].replace('Z', '+00:00'))
                self.results['duration_seconds'] = calculate_duration_seconds(start_dt, end_time)
            
            self.results['execution_status'] = 'failed'
            self.results['pipeline_status'] = 'failed'
            self.results['pipeline_complete'] = False
            
            return self.results
    
    def print_results(self, output_json: bool = False):
        """Print pipeline results."""
        if output_json:
            print(json.dumps(self.results, indent=2, default=str))
            return
        
        print("\n" + "=" * 80)
        print("PHASE 1 DIRECT CVE PIPELINE RESULTS")
        print("=" * 80)
        print(f"Timestamp (UTC): {self.results['timestamp_utc']}")
        print(f"CVE ID: {self.results['cve_id']}")
        print(f"Execution Status: {self.results['execution_status']}")
        print(f"Pipeline Status: {self.results['pipeline_status']}")
        print(f"Pipeline Complete: {self.results['pipeline_complete']}")
        
        if self.results['start_time'] and self.results['end_time']:
            print(f"Start Time: {self.results['start_time']}")
            print(f"End Time: {self.results['end_time']}")
            print(f"Duration: {self.results['duration_seconds']:.2f} seconds")
        
        print(f"\nContext Snapshot ID: {self.results['context_snapshot_id']}")
        print(f"Generation Run ID: {self.results['generation_run_id']}")
        print(f"Generation Status: {self.results['generation_status']}")
        print(f"QA Result: {self.results['qa_result']}")
        print(f"QA Score: {self.results['qa_score']}")
        
        if self.results['errors']:
            print(f"\nErrors ({len(self.results['errors'])}):")
            for error in self.results['errors']:
                print(f"  • {error}")
        
        print("=" * 80)


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Phase 1 direct CVE runner (no selection)')
    parser.add_argument('--cve', required=True, help='CVE ID to process')
    parser.add_argument('--json', action='store_true', help='Output JSON format only')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run pipeline
    runner = Phase1DirectCVERunner(args.cve)
    results = runner.run_pipeline()
    
    # Print results
    runner.print_results(args.json)
    
    # Exit code based on pipeline status
    if results['pipeline_status'] == 'success':
        print(f"\nPipeline successful for CVE: {args.cve}")
        sys.exit(0)
    elif results['pipeline_status'] == 'partial':
        print(f"\nPipeline partially successful for CVE: {args.cve}")
        sys.exit(1)
    else:
        print(f"\nPipeline failed for CVE: {args.cve}")
        sys.exit(1)


if __name__ == "__main__":
    main()