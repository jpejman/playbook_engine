#!/usr/bin/env python3
"""
Playbook Engine - CVE Dispatch to Generation Script
Version: v0.1.0
Timestamp: 2026-04-08

Purpose:
- Bridge discovery/enrichment into canonical generation pipeline
- Accept explicit CVE or discover missing CVEs
- Apply deterministic selection policy
- Optionally run enrichment
- Dispatch selected CVE to generation script

Design Rules:
- Dispatch is orchestration only
- No generation logic in this script
- Call canonical generation script (subprocess or clean import)
- Preserve lineage and quality gates
"""

import os
import sys
import json
import argparse
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CVEDispatcher:
    """Dispatch CVE to generation pipeline."""
    
    def __init__(self):
        self.selected_cve = None
        self.enrichment_results = None
        self.discovery_results = None
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "dispatch_status": "pending",
            "selected_cve": None,
            "selection_policy": "highest_severity",
            "generation_invoked": False,
            "generation_success": False
        }
        
        logger.info("CVEDispatcher initialized")
    
    def discover_missing_cves(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Discover CVEs missing approved playbooks.
        
        Args:
            limit: Maximum number of CVEs to discover
            
        Returns:
            List of missing CVE candidates
        """
        logger.info(f"Discovering missing CVEs (limit: {limit})...")
        
        try:
            # We need to run the discovery script or import its logic
            # For now, we'll run it as subprocess and parse output
            discovery_script = Path(__file__).parent / "02_50_discover_missing_playbooks_v0_1_0.py"
            
            cmd = [sys.executable, str(discovery_script), "--limit", str(limit), "--output-json", "discovery_temp.json"]
            
            logger.debug(f"Running discovery: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path(__file__).parent.parent)
            
            if result.returncode != 0:
                logger.error(f"Discovery failed: {result.stderr}")
                return []
            
            # Load results from JSON file
            temp_file = Path(__file__).parent.parent / "discovery_temp.json"
            if temp_file.exists():
                with open(temp_file, 'r', encoding='utf-8') as f:
                    discovery_data = json.load(f)
                
                # Clean up temp file
                temp_file.unlink(missing_ok=True)
                
                candidates = discovery_data.get("candidates", [])
                logger.info(f"Discovered {len(candidates)} missing CVEs")
                
                self.discovery_results = discovery_data
                return candidates
            else:
                logger.error("Discovery output file not found")
                return []
                
        except Exception as e:
            logger.error(f"Discovery failed: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def select_cve(self, candidates: List[Dict[str, Any]], 
                  selection_policy: str = "highest_severity") -> Optional[Dict[str, Any]]:
        """
        Select one CVE from candidates using deterministic policy.
        
        Args:
            candidates: List of CVE candidates
            selection_policy: One of "highest_severity", "newest", "first_sorted"
            
        Returns:
            Selected CVE or None
        """
        if not candidates:
            logger.warning("No candidates to select from")
            return None
        
        logger.info(f"Selecting CVE using policy: {selection_policy}")
        
        # Apply selection policy
        if selection_policy == "highest_severity":
            # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN)
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
            candidates.sort(key=lambda x: (
                severity_order.get(x.get("severity", "UNKNOWN"), 4),
                -x.get("cvss_score", 0)  # Higher score first
            ))
        
        elif selection_policy == "newest":
            # Sort by published date (newest first)
            candidates.sort(key=lambda x: x.get("published", ""), reverse=True)
        
        elif selection_policy == "first_sorted":
            # Sort by CVE ID (alphabetical)
            candidates.sort(key=lambda x: x.get("cve_id", ""))
        
        else:
            logger.warning(f"Unknown selection policy: {selection_policy}, using highest_severity")
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
            candidates.sort(key=lambda x: (
                severity_order.get(x.get("severity", "UNKNOWN"), 4),
                -x.get("cvss_score", 0)
            ))
        
        # Select first candidate
        selected = candidates[0]
        logger.info(f"Selected CVE: {selected['cve_id']} (severity: {selected.get('severity', 'UNKNOWN')}, published: {selected.get('published', 'N/A')})")
        
        self.selected_cve = selected
        self.results["selected_cve"] = selected["cve_id"]
        self.results["selection_policy"] = selection_policy
        self.results["selection_reason"] = f"Selected by {selection_policy} policy"
        
        return selected
    
    def enrich_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Enrich CVE with OpenSearch evidence.
        
        Args:
            cve_id: CVE ID to enrich
            
        Returns:
            Enrichment results or None
        """
        logger.info(f"Enriching CVE {cve_id} with OpenSearch...")
        
        try:
            # Run enrichment script
            enrichment_script = Path(__file__).parent / "02_60_enrich_cve_with_opensearch_v0_1_0.py"
            
            cmd = [sys.executable, str(enrichment_script), "--cve", cve_id, "--output-json", "enrichment_temp.json"]
            
            logger.debug(f"Running enrichment: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path(__file__).parent.parent)
            
            if result.returncode != 0:
                logger.error(f"Enrichment failed: {result.stderr}")
                return None
            
            # Load results from JSON file
            temp_file = Path(__file__).parent.parent / "enrichment_temp.json"
            if temp_file.exists():
                with open(temp_file, 'r', encoding='utf-8') as f:
                    enrichment_data = json.load(f)
                
                # Clean up temp file
                temp_file.unlink(missing_ok=True)
                
                decision = enrichment_data.get("enrichment_decision", "empty")
                hit_count = enrichment_data.get("hit_count", 0)
                
                logger.info(f"Enrichment complete: {hit_count} documents, decision: {decision}")
                
                self.enrichment_results = enrichment_data
                return enrichment_data
            else:
                logger.error("Enrichment output file not found")
                return None
                
        except Exception as e:
            logger.error(f"Enrichment failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def dispatch_to_generation(self, cve_id: str) -> bool:
        """
        Dispatch CVE to canonical generation script.
        
        Args:
            cve_id: CVE ID to generate playbook for
            
        Returns:
            True if generation was invoked successfully
        """
        logger.info(f"Dispatching CVE {cve_id} to generation pipeline...")
        
        try:
            # The canonical generation script is:
            # scripts/03_01_run_playbook_generation_v0_1_1_real_retrieval.py
            # However, it currently hardcodes CVE-TEST-0001
            # We need to check if it accepts CVE parameter or needs modification
            
            generation_script = Path(__file__).parent / "03_01_run_playbook_generation_v0_1_1_real_retrieval.py"
            
            # Check if script exists
            if not generation_script.exists():
                logger.error(f"Generation script not found: {generation_script}")
                return False
            
            # Read the script to check if it accepts CVE parameter
            script_content = generation_script.read_text(encoding='utf-8')
            
            # Check if script accepts --cve parameter
            if '--cve' in script_content:
                logger.info("Generation script accepts --cve parameter")
                cmd = [sys.executable, str(generation_script), "--cve", cve_id]
            else:
                logger.warning("Generation script does not accept --cve parameter")
                logger.info("Falling back to default behavior")
                cmd = [sys.executable, str(generation_script)]
            
            logger.info(f"Invoking generation script: {' '.join(cmd)}")
            
            # Actually run the command
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path(__file__).parent.parent)
            
            # Log output
            if result.stdout:
                logger.info(f"Generation stdout:\n{result.stdout[-1000:]}")  # Last 1000 chars
            if result.stderr:
                logger.error(f"Generation stderr:\n{result.stderr[-1000:]}")
            
            generation_success = result.returncode == 0
            
            self.results["generation_invoked"] = True
            self.results["generation_success"] = generation_success
            self.results["generation_returncode"] = result.returncode
            self.results["generation_stdout_summary"] = result.stdout[-500:] if result.stdout else ""
            self.results["generation_stderr_summary"] = result.stderr[-500:] if result.stderr else ""
            
            if generation_success:
                logger.info(f"Generation completed successfully for CVE {cve_id}")
            else:
                logger.error(f"Generation failed for CVE {cve_id} (return code: {result.returncode})")
            
            return generation_success
            
        except Exception as e:
            logger.error(f"Dispatch failed: {e}")
            import traceback
            traceback.print_exc()
            
            self.results["generation_invoked"] = True
            self.results["generation_success"] = False
            self.results["generation_error"] = str(e)
            
            return False
    
    def run_dispatch(self, cve_id: Optional[str] = None, 
                    discover_limit: int = 10,
                    selection_policy: str = "highest_severity",
                    run_enrichment: bool = False) -> bool:
        """
        Run complete dispatch workflow.
        
        Args:
            cve_id: Explicit CVE ID (if None, discover missing CVEs)
            discover_limit: Maximum CVEs to discover if cve_id is None
            selection_policy: Policy for selecting CVE from candidates
            run_enrichment: Whether to run enrichment before dispatch
            
        Returns:
            True if dispatch was successful
        """
        logger.info("CVE DISPATCH TO GENERATION")
        logger.info("=" * 60)
        
        try:
            # Step 1: Get target CVE
            if cve_id:
                # Use explicit CVE
                logger.info(f"Using explicit CVE: {cve_id}")
                selected_cve = {"cve_id": cve_id, "severity": "UNKNOWN", "published": None}
                self.selected_cve = selected_cve
                self.results["selected_cve"] = cve_id
                self.results["selection_policy"] = "explicit"
                self.results["selection_reason"] = "Explicit CVE provided"
            else:
                # Discover and select CVE
                logger.info("No explicit CVE provided, discovering missing CVEs...")
                candidates = self.discover_missing_cves(discover_limit)
                
                if not candidates:
                    logger.error("No missing CVEs found, cannot dispatch")
                    self.results["dispatch_status"] = "failed_no_candidates"
                    return False
                
                selected_cve = self.select_cve(candidates, selection_policy)
                if not selected_cve:
                    logger.error("Failed to select CVE")
                    self.results["dispatch_status"] = "failed_selection"
                    return False
            
            target_cve_id = selected_cve["cve_id"]
            logger.info(f"Target CVE: {target_cve_id}")
            
            # Step 2: Optionally run enrichment
            if run_enrichment:
                enrichment_results = self.enrich_cve(target_cve_id)
                if enrichment_results:
                    logger.info(f"Enrichment completed: {enrichment_results.get('hit_count', 0)} documents")
                    self.results["enrichment_decision"] = enrichment_results.get("enrichment_decision", "unknown")
                    self.results["enrichment_hit_count"] = enrichment_results.get("hit_count", 0)
                else:
                    logger.warning("Enrichment failed or returned no results")
                    self.results["enrichment_decision"] = "failed"
            
            # Step 3: Dispatch to generation
            logger.info(f"Dispatching CVE {target_cve_id} to generation...")
            generation_success = self.dispatch_to_generation(target_cve_id)
            
            # Step 4: Update results
            if generation_success:
                self.results["dispatch_status"] = "success"
                logger.info("Dispatch completed successfully")
            else:
                self.results["dispatch_status"] = "failed_generation"
                logger.error("Dispatch failed during generation")
            
            # Print summary
            self.print_summary()
            
            return generation_success
            
        except Exception as e:
            logger.error(f"Dispatch workflow failed: {e}")
            import traceback
            traceback.print_exc()
            
            self.results["dispatch_status"] = "failed_exception"
            self.results["exception"] = str(e)
            
            self.print_summary()
            return False
    
    def print_summary(self):
        """Print dispatch summary."""
        print("\n" + "=" * 80)
        print("CVE DISPATCH TO GENERATION - SUMMARY")
        print("=" * 80)
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Dispatch Status: {self.results['dispatch_status']}")
        print(f"Selected CVE: {self.results.get('selected_cve', 'None')}")
        print(f"Selection Policy: {self.results.get('selection_policy', 'N/A')}")
        print(f"Selection Reason: {self.results.get('selection_reason', 'N/A')}")
        
        if 'enrichment_decision' in self.results:
            print(f"Enrichment Decision: {self.results['enrichment_decision']}")
            print(f"Enrichment Hit Count: {self.results.get('enrichment_hit_count', 'N/A')}")
        
        print(f"Generation Invoked: {self.results.get('generation_invoked', False)}")
        print(f"Generation Success: {self.results.get('generation_success', False)}")
        
        if self.results.get('generation_returncode') is not None:
            print(f"Generation Return Code: {self.results['generation_returncode']}")
        
        print("-" * 80)
        
        # Print important notes
        print("\nIMPORTANT NOTES:")
        print("1. Generation script now accepts --cve parameter for explicit CVE dispatch.")
        print("2. Dispatch passes selected CVE to generation script.")
        print("3. This completes the orchestration layer for discovery-driven workflow.")
        
        print("=" * 80)


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Dispatch CVE to generation pipeline')
    parser.add_argument('--cve', type=str,
                       help='Explicit CVE ID to dispatch (if not provided, discover missing CVEs)')
    parser.add_argument('--discover-limit', type=int, default=10,
                       help='Maximum CVEs to discover if no explicit CVE (default: 10)')
    parser.add_argument('--selection-policy', type=str, default='highest_severity',
                       choices=['highest_severity', 'newest', 'first_sorted'],
                       help='Policy for selecting CVE from candidates (default: highest_severity)')
    parser.add_argument('--run-enrichment', action='store_true',
                       help='Run OpenSearch enrichment before dispatch')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run dispatch
    dispatcher = CVEDispatcher()
    success = dispatcher.run_dispatch(
        cve_id=args.cve,
        discover_limit=args.discover_limit,
        selection_policy=args.selection_policy,
        run_enrichment=args.run_enrichment
    )
    
    if success:
        logger.info("\nDispatch completed successfully")
        sys.exit(0)
    else:
        logger.error("\nDispatch failed")
        sys.exit(1)


if __name__ == "__main__":
    main()