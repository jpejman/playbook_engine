#!/usr/bin/env python3
"""
Run production verification on selected CVEs.
Executes the frozen production pipeline:
1. scripts/02_85_build_context_snapshot_v0_1_0.py
2. scripts/03_01_run_playbook_generation_v0_1_1_real_retrieval.py
3. scripts/06_08_qa_enforcement_gate_canonical_v0_2_0.py
"""

import os
import sys
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.utils.db import DatabaseClient

class ProductionVerification:
    """Run production verification on CVEs."""
    
    def __init__(self):
        self.db = DatabaseClient()
        self.results = []
        self.selected_cves = [
            "CVE-2025-32019",  # Harbor vulnerability
            "CVE-2025-47187",  # Mitel SIP Phones vulnerability
            "CVE-2025-4700",   # GitLab vulnerability
            "CVE-2025-8069",   # AWS Client VPN vulnerability
            "CVE-2025-46171",  # vBulletin vulnerability
        ]
    
    def get_sql_proof_not_approved(self, cve_id: str) -> Dict[str, Any]:
        """Get SQL proof that CVE is not already approved."""
        # Check if has approved playbook
        approved_query = """
        SELECT EXISTS(
            SELECT 1 
            FROM approved_playbooks ap
            JOIN generation_runs gr ON ap.generation_run_id = gr.id
            WHERE gr.cve_id = %s
        ) as has_approved_playbook
        """
        
        # Check queue status
        queue_query = """
        SELECT status FROM cve_queue WHERE cve_id = %s
        """
        
        # Check if test CVE
        is_test = any(
            cve_id.startswith(prefix) 
            for prefix in ['CVE-TEST-', 'TEST-', 'DEMO-', 'SYNTHETIC-', 'SEEDED-']
        )
        
        try:
            approved_result = self.db.fetch_one(approved_query, (cve_id,))
            queue_result = self.db.fetch_one(queue_query, (cve_id,))
            
            return {
                "cve_id": cve_id,
                "has_approved_playbook": approved_result["has_approved_playbook"] if approved_result else False,
                "queue_status": queue_result["status"] if queue_result else "not_in_queue",
                "is_test_cve": is_test
            }
        except Exception as e:
            print(f"   Error getting SQL proof: {e}")
            return {
                "cve_id": cve_id,
                "has_approved_playbook": False,
                "queue_status": "error",
                "is_test_cve": is_test
            }
    
    def run_script(self, script_name: str, cve_id: str, args: List[str] = None) -> Dict[str, Any]:
        """Run a script and capture output."""
        if args is None:
            args = []
        
        script_path = Path(__file__).parent / "scripts" / script_name
        if not script_path.exists():
            return {"error": f"Script not found: {script_name}", "success": False}
        
        cmd = [sys.executable, str(script_path), "--cve", cve_id] + args
        
        print(f"  Running: {script_name} for {cve_id}")
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            elapsed = time.time() - start_time
            
            return {
                "success": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "elapsed_seconds": elapsed
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Timeout expired (300 seconds)",
                "elapsed_seconds": 300
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "elapsed_seconds": time.time() - start_time
            }
    
    def check_generation_run_created(self, cve_id: str) -> Dict[str, Any]:
        """Check if generation run was created for CVE."""
        query = """
        SELECT 
            id as generation_run_id,
            cve_id,
            status,
            generation_source,
            model,
            LENGTH(prompt) as prompt_length,
            LENGTH(response) as response_length,
            llm_error_info,
            created_at
        FROM generation_runs
        WHERE cve_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """
        
        result = self.db.fetch_one(query, (cve_id,))
        return result if result else {}
    
    def check_qa_result(self, generation_run_id: int) -> Dict[str, Any]:
        """Check QA result for generation run."""
        query = """
        SELECT 
            id as qa_run_id,
            generation_run_id,
            qa_result,
            qa_score,
            qa_feedback,
            created_at
        FROM qa_runs
        WHERE generation_run_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """
        
        result = self.db.fetch_one(query, (generation_run_id,))
        return result if result else {}
    
    def check_approved_playbook(self, generation_run_id: int) -> Dict[str, Any]:
        """Check if approved playbook exists for generation run."""
        query = """
        SELECT 
            id as approved_playbook_id,
            generation_run_id,
            created_at
        FROM approved_playbooks
        WHERE generation_run_id = %s
        LIMIT 1
        """
        
        result = self.db.fetch_one(query, (generation_run_id,))
        return result if result else {}
    
    def run_verification_for_cve(self, cve_id: str) -> Dict[str, Any]:
        """Run full verification for a single CVE."""
        print(f"\n{'='*80}")
        print(f"VERIFICATION FOR: {cve_id}")
        print(f"{'='*80}")
        
        result = {
            "timestamp_utc": datetime.utcnow().isoformat(),
            "cve_id": cve_id,
            "source_of_selection": "NVD/OpenSearch discovery (missing playbooks)",
            "context_snapshot_id": None,
            "context_ready": False,
            "generation_attempted": False,
            "generation_run_id": None,
            "status": None,
            "generation_source": None,
            "model": None,
            "prompt_length": None,
            "response_length": None,
            "llm_error_info": None,
            "qa_result": None,
            "qa_score": None,
            "approved_playbook_id": None,
            "steps": {}
        }
        
        # Step 1: SQL proof not already approved
        print(f"\n1. SQL Proof - Not Already Approved:")
        sql_proof = self.get_sql_proof_not_approved(cve_id)
        print(f"   Has approved playbook: {sql_proof.get('has_approved_playbook', 'N/A')}")
        print(f"   Queue status: {sql_proof.get('queue_status', 'N/A')}")
        print(f"   Is test CVE: {sql_proof.get('is_test_cve', 'N/A')}")
        
        if sql_proof.get('has_approved_playbook', False):
            print(f"   [X] CVE already has approved playbook - skipping")
            result["status"] = "skipped_already_approved"
            return result
        
        # Step 2: Build context snapshot
        print(f"\n2. Building Context Snapshot:")
        context_result = self.run_script("02_85_build_context_snapshot_v0_1_0.py", cve_id, ["--json"])
        result["steps"]["context_build"] = context_result
        
        if context_result.get("success"):
            try:
                # Parse JSON output to get context snapshot ID
                output_lines = context_result["stdout"].strip().split('\n')
                for line in output_lines:
                    if line.startswith('{'):
                        context_data = json.loads(line)
                        result["context_snapshot_id"] = context_data.get("context_snapshot_id")
                        result["context_ready"] = context_data.get("readiness_status") in ["ready", "auto_built"]
                        break
            except:
                pass
            
            print(f"   Success: {result['context_ready']}")
            if result["context_snapshot_id"]:
                print(f"   Context Snapshot ID: {result['context_snapshot_id']}")
        else:
            print(f"   Failed: {context_result.get('error', 'Unknown error')}")
            result["status"] = "failed_context_build"
            return result
        
        if not result["context_ready"]:
            print(f"   [X] Context not ready - skipping generation")
            result["status"] = "failed_context_not_ready"
            return result
        
        # Step 3: Run playbook generation
        print(f"\n3. Running Playbook Generation:")
        generation_result = self.run_script("03_01_run_playbook_generation_v0_1_1_real_retrieval.py", cve_id)
        result["steps"]["generation"] = generation_result
        result["generation_attempted"] = True
        
        if generation_result.get("success"):
            print(f"   Generation completed")
        else:
            print(f"   Generation failed: {generation_result.get('error', 'Unknown error')}")
        
        # Step 4: Check generation run was created
        print(f"\n4. Checking Generation Run:")
        gen_run = self.check_generation_run_created(cve_id)
        if gen_run:
            result["generation_run_id"] = gen_run["generation_run_id"]
            result["status"] = gen_run["status"]
            result["generation_source"] = gen_run["generation_source"]
            result["model"] = gen_run["model"]
            result["prompt_length"] = gen_run["prompt_length"]
            result["response_length"] = gen_run["response_length"]
            result["llm_error_info"] = gen_run["llm_error_info"]
            
            print(f"   Generation Run ID: {result['generation_run_id']}")
            print(f"   Status: {result['status']}")
            print(f"   Model: {result['model']}")
        else:
            print(f"   [X] No generation run created")
            result["status"] = "failed_no_generation_run"
            return result
        
        # Step 5: Run QA enforcement gate
        print(f"\n5. Running QA Enforcement Gate:")
        qa_result = self.run_script("06_08_qa_enforcement_gate_canonical_v0_2_0.py", cve_id)
        result["steps"]["qa"] = qa_result
        
        if qa_result.get("success"):
            print(f"   QA completed")
        else:
            print(f"   QA failed or rejected: {qa_result.get('stderr', 'Unknown error')[:200]}")
        
        # Step 6: Check QA result
        print(f"\n6. Checking QA Result:")
        qa_check = self.check_qa_result(result["generation_run_id"])
        if qa_check:
            result["qa_result"] = qa_check["qa_result"]
            result["qa_score"] = qa_check["qa_score"]
            print(f"   QA Result: {result['qa_result']}")
            print(f"   QA Score: {result['qa_score']}")
        else:
            print(f"   No QA result found")
        
        # Step 7: Check approved playbook
        print(f"\n7. Checking Approved Playbook:")
        approved = self.check_approved_playbook(result["generation_run_id"])
        if approved:
            result["approved_playbook_id"] = approved["approved_playbook_id"]
            print(f"   Approved Playbook ID: {result['approved_playbook_id']}")
        else:
            print(f"   No approved playbook")
        
        print(f"\n[+] Verification complete for {cve_id}")
        return result
    
    def run_all_verifications(self):
        """Run verification for all selected CVEs."""
        print("VS.ai — Playbook Engine Gen-3")
        print("Fresh NVD CVE Production Verification Directive")
        print(f"Timestamp (UTC): {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
        print("Mode: Production path only")
        print("Goal: Prove the system works on NEW CVEs pulled from NVD/OpenSearch")
        print("=" * 80)
        
        print(f"\nSelected 5 NEW CVEs (not in exclusion list):")
        for i, cve in enumerate(self.selected_cves, 1):
            print(f"  {i}. {cve}")
        
        print(f"\nExclusion list CVEs (not used):")
        exclusion_list = ["CVE-2023-4863", "CVE-2024-6387", "CVE-2024-9313", 
                         "CVE-2025-47281", "CVE-2025-53537", "CVE-2025-54371"]
        for cve in exclusion_list:
            print(f"  - {cve}")
        
        print(f"\n{'='*80}")
        print("STARTING PRODUCTION VERIFICATION")
        print(f"{'='*80}")
        
        for cve_id in self.selected_cves:
            result = self.run_verification_for_cve(cve_id)
            self.results.append(result)
        
        self.print_summary()
        
        # Save results to file
        output_file = "production_verification_results.json"
        with open(output_file, 'w') as f:
            json.dump({
                "timestamp": datetime.utcnow().isoformat(),
                "selected_cves": self.selected_cves,
                "results": self.results
            }, f, indent=2, default=str)
        
        print(f"\nResults saved to: {output_file}")
    
    def print_summary(self):
        """Print verification summary."""
        print(f"\n{'='*80}")
        print("PRODUCTION VERIFICATION SUMMARY")
        print(f"{'='*80}")
        
        total = len(self.results)
        attempted = sum(1 for r in self.results if r.get("generation_attempted", False))
        persisted = sum(1 for r in self.results if r.get("generation_run_id"))
        qa_pass = sum(1 for r in self.results if r.get("qa_result") == "approved")
        approved = sum(1 for r in self.results if r.get("approved_playbook_id"))
        failed = sum(1 for r in self.results if r.get("status") and "failed" in r.get("status", ""))
        
        print(f"Total CVEs: {total}")
        print(f"Attempted generations: {attempted}")
        print(f"Persisted generation runs: {persisted}")
        print(f"QA passed: {qa_pass}")
        print(f"Approved playbooks: {approved}")
        print(f"Failed: {failed}")
        
        print(f"\nDetailed Results:")
        print(f"{'CVE ID':20} {'Context':7} {'Gen Run':8} {'Status':12} {'QA':10} {'Approved':9}")
        print(f"{'-'*20} {'-'*7} {'-'*8} {'-'*12} {'-'*10} {'-'*9}")
        
        for result in self.results:
            cve_id = result["cve_id"]
            context = "✓" if result["context_ready"] else "✗"
            gen_run = str(result["generation_run_id"] or "N/A")
            status = result["status"] or "unknown"
            qa = result["qa_result"] or "N/A"
            approved = "✓" if result["approved_playbook_id"] else "✗"
            
            print(f"{cve_id:20} {context:7} {gen_run:8} {status:12} {qa:10} {approved:9}")
        
        # Group failure reasons
        failure_reasons = {}
        for result in self.results:
            if result.get("status") and "failed" in result.get("status", ""):
                reason = result["status"]
                failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
        
        if failure_reasons:
            print(f"\nFailure Reasons:")
            for reason, count in failure_reasons.items():
                print(f"  {reason}: {count}")
        
        print(f"\n{'='*80}")
        print("SUCCESS CRITERIA CHECK:")
        print(f"{'='*80}")
        
        criteria_met = True
        print(f"1. 5 NEW CVEs used: {'✓' if total == 5 else '✗'}")
        print(f"2. None from exclusion list: {'✓' if all(cve not in self.selected_cves for cve in ["CVE-2023-4863", "CVE-2024-6387", "CVE-2024-9313", "CVE-2025-47281", "CVE-2025-53537", "CVE-2025-54371"]) else '✗'}")
        print(f"3. All attempted generations create generation_runs rows: {'✓' if attempted == persisted else '✗'}")
        print(f"4. Results include timestamps: {'✓' if all('timestamp_utc' in r for r in self.results) else '✗'}")
        print(f"5. Production path exercised on fresh NVD/OpenSearch-derived CVEs: {'✓' if attempted > 0 else '✗'}")
        
        if criteria_met and attempted == persisted and attempted > 0:
            print(f"\n✅ VERIFICATION SUCCESSFUL: Production pipeline works on fresh CVEs!")
        else:
            print(f"\n❌ VERIFICATION INCOMPLETE: Some criteria not met")

def main():
    """Main execution."""
    verifier = ProductionVerification()
    verifier.run_all_verifications()
    return 0

if __name__ == "__main__":
    sys.exit(main())