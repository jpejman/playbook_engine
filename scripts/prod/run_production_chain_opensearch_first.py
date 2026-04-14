#!/usr/bin/env python3
"""
VS.ai — Playbook Engine Gen-3
OpenSearch-First Production Chain Runner
Version: v1.0.0
Timestamp (UTC): 2026-04-10

Purpose:
- Run complete production chain with OpenSearch-first selected CVE
- Execute: selector → context snapshot → generation → QA
- Return required output with all metrics
"""

import sys
import json
import subprocess
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.prod.production_selector_opensearch_first import OpenSearchFirstSelector
from scripts.prod.time_utils import get_utc_now, datetime_to_iso

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ProductionChainRunner:
    """Run complete production chain with OpenSearch-first selected CVE."""
    
    def __init__(self):
        self.results = {
            "timestamp_utc": datetime_to_iso(get_utc_now()),
            "selected_cve": None,
            "source_of_selection": "OpenSearch NVD",
            "number_of_candidates_returned_from_opensearch": 0,
            "number_filtered_out_by_postgres": 0,
            "reason_selected": [],
            "context_snapshot_id": None,
            "generation_run_id": None,
            "generation_source": "real_retrieval",
            "status": "not_started",
            "response_length": 0,
            "llm_error_info": None,
            "qa_result": None,
            "qa_score": None,
            "chain_complete": False,
            "errors": []
        }
        
        logger.info("ProductionChainRunner initialized")
    
    def run_selection(self, limit: int = 50) -> Optional[Dict[str, Any]]:
        """Run OpenSearch-first selection."""
        logger.info("Step 1: Running OpenSearch-first selection...")
        
        try:
            selector = OpenSearchFirstSelector()
            selection_results = selector.run_selection(limit)
            
            if not selection_results.get('selected_cve'):
                error_msg = "No CVE selected from OpenSearch-first selector"
                logger.error(error_msg)
                self.results['errors'].append(error_msg)
                return None
            
            # Update results with selection data
            self.results['selected_cve'] = selection_results['selected_cve']
            self.results['number_of_candidates_returned_from_opensearch'] = selection_results['number_of_candidates_returned_from_opensearch']
            self.results['number_filtered_out_by_postgres'] = selection_results['number_filtered_out_by_postgres']
            self.results['reason_selected'] = selection_results['reason_selected']
            
            logger.info(f"Selected CVE: {self.results['selected_cve']}")
            return selection_results
            
        except Exception as e:
            error_msg = f"Selection failed: {e}"
            logger.error(error_msg)
            self.results['errors'].append(error_msg)
            return None
    
    def run_context_snapshot(self, cve_id: str) -> Optional[int]:
        """Run context snapshot builder."""
        logger.info(f"Step 2: Building context snapshot for {cve_id}...")
        
        try:
            # Run the context snapshot script
            cmd = [
                sys.executable, 
                "scripts/prod/02_85_build_context_snapshot_v0_1_0.py",
                "--cve", cve_id,
                "--json"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent.parent
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
    
    def run_generation(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Run playbook generation."""
        logger.info(f"Step 3: Running playbook generation for {cve_id}...")
        
        try:
            # Run the generation script
            cmd = [
                sys.executable,
                "scripts/prod/03_01_run_playbook_generation_v0_1_1_real_retrieval.py",
                "--cve", cve_id
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent.parent
            )
            
            # The generation script doesn't output JSON, so we need to parse the log output
            # Look for key information in the output
            generation_data = {
                "status": "unknown",
                "generation_run_id": None,
                "response_length": 0,
                "llm_error_info": None
            }
            
            # Parse the output to find key information
            output_lines = result.stdout.split('\n')
            for line in output_lines:
                if "Generation Run ID:" in line:
                    parts = line.split("Generation Run ID:")
                    if len(parts) > 1:
                        generation_data["generation_run_id"] = parts[1].strip()
                elif "LLM response received:" in line:
                    parts = line.split("LLM response received:")
                    if len(parts) > 1:
                        length_str = parts[1].strip().split()[0]  # Get "5597 chars"
                        generation_data["response_length"] = int(length_str)
                elif "Final generation status:" in line:
                    parts = line.split("Final generation status:")
                    if len(parts) > 1:
                        generation_data["status"] = parts[1].strip()
                elif "LLM error info stored:" in line:
                    parts = line.split("LLM error info stored:")
                    if len(parts) > 1:
                        generation_data["llm_error_info"] = parts[1].strip()
            
            # Extract generation info
            generation_run_id = generation_data.get('generation_run_id')
            status = generation_data.get('status', 'failed')
            response_length = generation_data.get('response_length', 0)
            llm_error_info = generation_data.get('llm_error_info')
            
            self.results['generation_run_id'] = generation_run_id
            self.results['status'] = status
            self.results['response_length'] = response_length
            self.results['llm_error_info'] = llm_error_info
            
            if generation_run_id:
                logger.info(f"Generation run created: ID {generation_run_id}, status: {status}")
            else:
                logger.warning(f"Generation may have failed: status={status}")
            
            return generation_data
            
        except Exception as e:
            error_msg = f"Generation execution failed: {e}"
            logger.error(error_msg)
            self.results['errors'].append(error_msg)
            self.results['status'] = 'execution_failed'
            return None
    
    def run_qa(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Run QA enforcement."""
        logger.info(f"Step 4: Running QA enforcement for {cve_id}...")
        
        try:
            # Run the QA script
            cmd = [
                sys.executable,
                "scripts/prod/06_08_qa_enforcement_gate_canonical_v0_2_0.py",
                "--cve", cve_id
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent.parent
            )
            
            # The QA script doesn't output JSON, so we need to parse the log output
            qa_data: Dict[str, Any] = {
                "result": None,
                "score": None
            }
            
            # Parse the output to find key information
            output_lines = result.stdout.split('\n')
            for line in output_lines:
                if "QA Result:" in line:
                    parts = line.split("QA Result:")
                    if len(parts) > 1:
                        qa_data["result"] = parts[1].strip()
                elif "QA Score:" in line:
                    parts = line.split("QA Score:")
                    if len(parts) > 1:
                        score_str = parts[1].strip()
                        try:
                            qa_data["score"] = float(score_str)
                        except ValueError:
                            qa_data["score"] = 0.0
            
            # Extract QA info
            qa_result = qa_data.get('result')
            qa_score = qa_data.get('score')
            
            self.results['qa_result'] = qa_result
            self.results['qa_score'] = qa_score
            
            if qa_result:
                logger.info(f"QA result: {qa_result}, score: {qa_score}")
            else:
                logger.warning(f"QA may have failed: no result found in output")
            
            return qa_data
            
        except Exception as e:
            error_msg = f"QA execution failed: {e}"
            logger.error(error_msg)
            self.results['errors'].append(error_msg)
            return None
    
    def run_chain(self, limit: int = 50) -> Dict[str, Any]:
        """Run complete production chain."""
        logger.info("Starting OpenSearch-first production chain...")
        
        # Step 1: Selection
        selection_results = self.run_selection(limit)
        if not selection_results:
            self.results['chain_complete'] = False
            return self.results
        
        cve_id = self.results['selected_cve']
        
        # Step 2: Context snapshot
        context_snapshot_id = self.run_context_snapshot(cve_id)
        if not context_snapshot_id:
            self.results['chain_complete'] = False
            return self.results
        
        # Step 3: Generation
        generation_data = self.run_generation(cve_id)
        if not generation_data:
            self.results['chain_complete'] = False
            return self.results
        
        # Step 4: QA
        qa_data = self.run_qa(cve_id)
        
        # Mark chain as complete (even if QA failed, we still completed the main chain)
        self.results['chain_complete'] = True
        logger.info("Production chain completed")
        
        return self.results
    
    def print_results(self, output_json: bool = False):
        """Print production chain results."""
        if output_json:
            print(json.dumps(self.results, indent=2, default=str))
            return
        
        print("\n" + "=" * 80)
        print("OPENSEARCH-FIRST PRODUCTION CHAIN RESULTS")
        print("=" * 80)
        print(f"Timestamp (UTC): {self.results['timestamp_utc']}")
        print(f"Source of Selection: {self.results['source_of_selection']}")
        print(f"Candidates from OpenSearch NVD: {self.results['number_of_candidates_returned_from_opensearch']}")
        print(f"Filtered out by PostgreSQL: {self.results['number_filtered_out_by_postgres']}")
        
        if self.results['selected_cve']:
            print(f"\nSELECTED CVE: {self.results['selected_cve']}")
            print("-" * 40)
            print("Selection Reasons:")
            for reason in self.results['reason_selected']:
                print(f"  • {reason}")
            
            print(f"\nContext Snapshot ID: {self.results['context_snapshot_id']}")
            print(f"Generation Run ID: {self.results['generation_run_id']}")
            print(f"Generation Source: {self.results['generation_source']}")
            print(f"Status: {self.results['status']}")
            print(f"Response Length: {self.results['response_length']}")
            
            if self.results['llm_error_info']:
                print(f"LLM Error Info: {self.results['llm_error_info']}")
            
            print(f"QA Result: {self.results['qa_result']}")
            print(f"QA Score: {self.results['qa_score']}")
            
            print(f"\nChain Complete: {self.results['chain_complete']}")
        else:
            print("\nNO CVE SELECTED")
        
        if self.results['errors']:
            print(f"\nErrors ({len(self.results['errors'])}):")
            for error in self.results['errors']:
                print(f"  • {error}")
        
        print("=" * 80)


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='OpenSearch-first production chain runner')
    parser.add_argument('--limit', type=int, default=50, help='Maximum CVEs to query from OpenSearch (default: 50)')
    parser.add_argument('--json', action='store_true', help='Output JSON format only')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run production chain
    runner = ProductionChainRunner()
    results = runner.run_chain(args.limit)
    
    # Print results
    runner.print_results(args.json)
    
    # Exit code
    if results['chain_complete']:
        print(f"\nProduction chain completed for CVE: {results['selected_cve']}")
        sys.exit(0)
    else:
        print(f"\nProduction chain failed: {len(results['errors'])} errors")
        sys.exit(1)


if __name__ == "__main__":
    main()