#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Service: VS.ai Playbook Engine
Script: Select Next Missing CVE
File: 06_07b_select_next_missing_cve_v0_1_0.py
Version: v0.1.0
Timestamp (UTC): 2026-04-08

Purpose:
    Select ONE next eligible CVE from missing candidates.
    Enforce selection rules:
    1. NOT already approved
    2. NOT completed
    3. NOT currently processing
    4. NOT same as last processed CVE
    5. has enrichment or can be enriched

Usage:
    python scripts/06_07b_select_next_missing_cve_v0_1_0.py [--force] [--json]
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Sequence

# Adjust path if needed depending on your repo layout
sys.path.append(".")

from src.utils.db import DatabaseClient


# -----------------------------------------------------------------------------
# Selection Rules & Scoring
# -----------------------------------------------------------------------------

class CVESelector:
    """Select next missing CVE based on rules and scoring."""
    
    def __init__(self, db: DatabaseClient, allow_test_cves: bool = False):
        self.db = db
        self.allow_test_cves = allow_test_cves
        self.last_processed_cve = self._get_last_processed_cve()
        self.candidates = []
        self.selected_cve = None
        self.selection_reasoning = []
        
    def _get_last_processed_cve(self) -> Optional[str]:
        """Get the most recently processed CVE."""
        query = """
        SELECT cve_id
        FROM generation_runs
        WHERE created_at IS NOT NULL
        ORDER BY created_at DESC
        LIMIT 1
        """
        result = self.db.fetch_one(query)
        return result["cve_id"] if result else None
    
    def get_candidates(self) -> Sequence[Dict[str, Any]]:
        """Get all candidate CVEs using similar logic to listing script."""
        query = """
        WITH 
        -- CVEs with approved playbooks
        approved_cves AS (
            SELECT DISTINCT gr.cve_id
            FROM approved_playbooks ap
            JOIN generation_runs gr ON ap.generation_run_id = gr.id
        ),
        -- CVEs currently being processed (in progress generation runs)
        processing_cves AS (
            SELECT DISTINCT cve_id
            FROM generation_runs
            WHERE status IN ('in_progress', 'processing')
            AND created_at > NOW() - INTERVAL '1 hour'
        ),
        -- CVEs with context snapshots
        cves_with_context AS (
            SELECT DISTINCT cve_id
            FROM cve_context_snapshot
            WHERE context_data IS NOT NULL
        ),
        -- CVEs with enrichment data (placeholder - table may not exist)
        cves_with_enrichment AS (
            SELECT DISTINCT cve_id
            FROM cve_context_snapshot
            WHERE context_data IS NOT NULL
            AND (context_data->>'vendor' IS NOT NULL OR context_data->>'product' IS NOT NULL)
        )
        SELECT 
            q.cve_id,
            q.status as queue_status,
            q.priority,
            q.created_at as queue_created,
            -- Check if CVE has approved playbook
            CASE WHEN ac.cve_id IS NOT NULL THEN TRUE ELSE FALSE END as has_approved_playbook,
            -- Check if CVE has generation run
            CASE WHEN gr.id IS NOT NULL THEN TRUE ELSE FALSE END as has_generation_run,
            -- Check if CVE has context snapshot
            CASE WHEN ccs.cve_id IS NOT NULL THEN TRUE ELSE FALSE END as has_context_snapshot,
            -- Check if CVE has enrichment
            CASE WHEN ce.cve_id IS NOT NULL THEN TRUE ELSE FALSE END as has_enrichment,
            -- Check if CVE is currently being processed
            CASE WHEN pc.cve_id IS NOT NULL THEN TRUE ELSE FALSE END as is_processing,
            -- Get latest generation status if exists
            gr.status as latest_generation_status,
            gr.created_at as latest_generation_date,
            -- Get vendor/product from context if available
            NULL as vendor,
            NULL as product,
            NULL as severity,
            -- Get queue processing attempts
            q.retry_count as attempt_count,
            q.updated_at as last_attempt_at,
            -- Determine if CVE is a test CVE
            CASE 
                WHEN q.cve_id LIKE 'CVE-TEST-%' THEN TRUE
                WHEN q.cve_id LIKE 'TEST-%' THEN TRUE
                WHEN q.cve_id LIKE 'DEMO-%' THEN TRUE
                WHEN q.cve_id LIKE 'SYNTHETIC-%' THEN TRUE
                WHEN q.cve_id LIKE 'SEEDED-%' THEN TRUE
                ELSE FALSE
            END as is_test_cve
        FROM cve_queue q
        LEFT JOIN approved_cves ac ON q.cve_id = ac.cve_id
        LEFT JOIN (
            SELECT DISTINCT ON (cve_id) cve_id, status, created_at, id
            FROM generation_runs
            ORDER BY cve_id, created_at DESC
        ) gr ON q.cve_id = gr.cve_id
        LEFT JOIN processing_cves pc ON q.cve_id = pc.cve_id
        LEFT JOIN cves_with_context ccs ON q.cve_id = ccs.cve_id
        LEFT JOIN cves_with_enrichment ce ON q.cve_id = ce.cve_id
        WHERE 
            -- Only CVEs in queue
            q.cve_id IS NOT NULL
            -- Not completed
            AND q.status NOT IN ('completed', 'archived')
        ORDER BY 
            q.created_at ASC
        """
        
        candidates = self.db.fetch_all(query)
        
        # Filter test CVEs if not allowed
        if not self.allow_test_cves:
            filtered_candidates = []
            for candidate in candidates:
                if not candidate.get("is_test_cve", False):
                    filtered_candidates.append(candidate)
            return filtered_candidates
        
        return candidates
    
    def apply_selection_rules(self, candidate: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Apply selection rules to candidate.
        
        Returns:
            Tuple of (is_eligible, list_of_reasons)
        """
        reasons = []
        eligible = True
        
        # Rule 1: NOT already approved
        if candidate.get("has_approved_playbook"):
            eligible = False
            reasons.append("Already has approved playbook")
        
        # Rule 2: NOT completed (queue status)
        queue_status = candidate.get("queue_status", "")
        if queue_status in ["completed", "archived"]:
            eligible = False
            reasons.append(f"Queue status is '{queue_status}'")
        
        # Rule 3: NOT currently processing
        if candidate.get("is_processing") and candidate.get("queue_status") != "failed":
            eligible = False
            reasons.append("Currently being processed")
        
        # Rule 4: NOT same as last processed CVE
        if candidate["cve_id"] == self.last_processed_cve:
            eligible = False
            reasons.append("Same as last processed CVE")
        
        # Rule 5: NOT a test CVE unless explicitly allowed
        if candidate.get("is_test_cve") and not self.allow_test_cves:
            eligible = False
            reasons.append("Test CVE (use --allow-test-cves to include)")
        
        # Rule 6: has enrichment or can be enriched
        # We'll score this rather than reject - CVEs without enrichment get lower score
        if not candidate.get("has_context_snapshot") and not candidate.get("has_enrichment"):
            reasons.append("Missing context/enrichment - will need enrichment step")
        
        # Additional rule: Check generation status if exists
        if candidate.get("has_generation_run"):
            gen_status = candidate.get("latest_generation_status", "")
            if gen_status in ["completed", "approved"]:
                eligible = False
                reasons.append(f"Generation status is '{gen_status}'")
            elif gen_status == "failed":
                reasons.append("Previous generation failed - may need retry")
        
        return eligible, reasons
    
    def calculate_score(self, candidate: Dict[str, Any]) -> float:
        """Calculate selection score for candidate (0.0-1.0)."""
        score = 0.0
        
        # Base score for being in queue
        score += 0.1
        
        # Priority scoring (higher priority = higher score)
        priority = candidate.get("priority", 5)
        if priority <= 1:
            score += 0.3  # Critical
        elif priority <= 3:
            score += 0.2  # High
        elif priority <= 5:
            score += 0.1  # Medium
        
        # Context/enrichment scoring
        if candidate.get("has_context_snapshot"):
            score += 0.25
        if candidate.get("has_enrichment"):
            score += 0.15
        
        # Vendor/product information
        if candidate.get("vendor") and candidate.get("product"):
            score += 0.1
        
        # Severity scoring
        severity = candidate.get("severity")
        if severity:
            severity = severity.upper()
            if severity == "CRITICAL":
                score += 0.2
            elif severity == "HIGH":
                score += 0.15
            elif severity == "MEDIUM":
                score += 0.1
            elif severity == "LOW":
                score += 0.05
        
        # Queue age (older items get slightly higher score)
        # This is handled by ordering in main selection
        
        # Failed attempts (more attempts = slightly lower score)
        attempts = candidate.get("attempt_count", 0)
        if attempts > 0:
            score -= min(0.1 * attempts, 0.3)  # Max penalty of 0.3
        
        # Penalize test CVEs even if allowed
        if candidate.get("is_test_cve"):
            score -= 0.5  # Significant penalty for test CVEs
        
        return min(max(score, 0.0), 1.0)
    
    def select_next_cve(self, force: bool = False) -> Optional[Dict[str, Any]]:
        """Select the next CVE based on rules and scoring."""
        self.candidates = self.get_candidates()
        
        if not self.candidates:
            self.selection_reasoning.append("No candidates found in queue")
            return None
        
        # Apply rules and filter eligible candidates
        eligible_candidates = []
        for candidate in self.candidates:
            eligible, reasons = self.apply_selection_rules(candidate)
            
            if eligible or force:
                score = self.calculate_score(candidate)
                candidate["selection_score"] = score
                candidate["selection_reasons"] = reasons
                eligible_candidates.append(candidate)
            else:
                self.selection_reasoning.append(
                    f"CVE {candidate['cve_id']} ineligible: {', '.join(reasons)}"
                )
        
        if not eligible_candidates:
            self.selection_reasoning.append("No eligible candidates after applying rules")
            return None
        
        # Sort by score (descending), then queue age (ascending)
        eligible_candidates.sort(
            key=lambda x: (-x["selection_score"], x["queue_created"])
        )
        
        # Select top candidate
        self.selected_cve = eligible_candidates[0]
        
        # Build selection reasoning
        self.selection_reasoning.append(
            f"Selected CVE {self.selected_cve['cve_id']} with score {self.selected_cve['selection_score']:.2f}"
        )
        
        if self.selected_cve.get("has_context_snapshot"):
            self.selection_reasoning.append("Has context snapshot available")
        else:
            self.selection_reasoning.append("Will require enrichment step")
        
        if self.selected_cve.get("vendor") and self.selected_cve.get("product"):
            self.selection_reasoning.append(
                f"Target: {self.selected_cve['vendor']}/{self.selected_cve['product']}"
            )
        
        if self.selected_cve.get("severity"):
            self.selection_reasoning.append(f"Severity: {self.selected_cve['severity']}")
        
        return self.selected_cve
    
    def get_sql_proof(self, cve_id: str) -> Dict[str, Any]:
        """Get SQL proof that CVE is missing approved playbook."""
        # First check if it's a test CVE in Python
        is_test = (
            cve_id.startswith('CVE-TEST-') or
            cve_id.startswith('TEST-') or
            cve_id.startswith('DEMO-') or
            cve_id.startswith('SYNTHETIC-') or
            cve_id.startswith('SEEDED-')
        )
        
        query = """
        WITH 
        -- Check if CVE has approved playbook
        has_approved AS (
            SELECT EXISTS (
                SELECT 1 
                FROM approved_playbooks ap
                JOIN generation_runs gr ON ap.generation_run_id = gr.id
                WHERE gr.cve_id = %s
            ) as has_approved_playbook
        ),
        -- Check if CVE is in queue and status
        queue_status AS (
            SELECT status, priority, created_at
            FROM cve_queue
            WHERE cve_id = %s
        ),
        -- Check if CVE has generation runs
        generation_info AS (
            SELECT status, created_at
            FROM generation_runs
            WHERE cve_id = %s
            ORDER BY created_at DESC
            LIMIT 1
        ),
        -- Check if CVE has context snapshot
        context_info AS (
            SELECT EXISTS (
                SELECT 1 
                FROM cve_context_snapshot
                WHERE cve_id = %s AND context_data IS NOT NULL
            ) as has_context
        )
        SELECT 
            ha.has_approved_playbook,
            COALESCE(qs.status, 'not_in_queue') as queue_status,
            COALESCE(qs.priority, 0) as queue_priority,
            qs.created_at as queue_created,
            COALESCE(gi.status, 'no_generation') as latest_generation_status,
            gi.created_at as latest_generation_date,
            ci.has_context
        FROM has_approved ha
        LEFT JOIN queue_status qs ON TRUE
        LEFT JOIN generation_info gi ON TRUE
        LEFT JOIN context_info ci ON TRUE
        """
        
        result = self.db.fetch_one(query, (cve_id, cve_id, cve_id, cve_id))
        if result:
            result["is_test"] = is_test
        return result if result else {}
    
    def get_selection_output(self) -> Dict[str, Any]:
        """Get structured output for selection."""
        if not self.selected_cve:
            return {
                "selected": False,
                "timestamp": datetime.utcnow().isoformat(),
                "reasoning": self.selection_reasoning,
                "total_candidates": len(self.candidates),
                "eligible_candidates": 0
            }
        
        # Get SQL proof for selected CVE
        sql_proof = self.get_sql_proof(self.selected_cve["cve_id"])
        
        return {
            "selected": True,
            "timestamp": datetime.utcnow().isoformat(),
            "cve_id": self.selected_cve["cve_id"],
            "queue_status": self.selected_cve["queue_status"],
            "priority": self.selected_cve["priority"],
            "has_context_snapshot": self.selected_cve.get("has_context_snapshot", False),
            "has_enrichment": self.selected_cve.get("has_enrichment", False),
            "is_test_cve": self.selected_cve.get("is_test_cve", False),
            "vendor": self.selected_cve.get("vendor"),
            "product": self.selected_cve.get("product"),
            "severity": self.selected_cve.get("severity"),
            "selection_score": self.selected_cve.get("selection_score", 0.0),
            "reasoning": self.selection_reasoning,
            "total_candidates": len(self.candidates),
            "eligible_candidates": len([c for c in self.candidates if "selection_score" in c]),
            "allow_test_cves": self.allow_test_cves,
            "sql_proof": sql_proof
        }


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true",
                       help="Force selection even if rules would normally exclude")
    parser.add_argument("--allow-test-cves", action="store_true",
                       help="Allow test CVEs (CVE-TEST-*, TEST-*, etc.)")
    parser.add_argument("--json", action="store_true",
                       help="Output JSON format only")
    parser.add_argument("--verbose", action="store_true",
                       help="Show detailed reasoning")
    args = parser.parse_args()
    
    print("=" * 80)
    print(f"[SELECT NEXT MISSING CVE] Starting selection (force: {args.force}, allow_test_cves: {args.allow_test_cves})")
    print("=" * 80)
    
    db = DatabaseClient()
    selector = CVESelector(db, args.allow_test_cves)
    
    # Select next CVE
    selected = selector.select_next_cve(args.force)
    
    if args.json:
        # Output JSON only
        output = selector.get_selection_output()
        print(json.dumps(output, indent=2, default=str))
    else:
        # Print human-readable output
        if not selected:
            print("\n[ERROR] No CVE selected")
            print("\nSelection Reasoning:")
            for reason in selector.selection_reasoning:
                print(f"  - {reason}")
            sys.exit(1)
        
        print(f"\n[SELECTED] CVE: {selected['cve_id']}")
        print("-" * 80)
        
        print(f"Queue Status:      {selected['queue_status']}")
        print(f"Priority:          {selected['priority']}")
        print(f"Selection Score:   {selected.get('selection_score', 0.0):.2f}")
        
        if selected.get('is_test_cve'):
            print(f"TEST CVE:        Yes (use --allow-test-cves to include)")
        
        if selected.get('vendor') or selected.get('product'):
            print(f"Vendor/Product:    {selected.get('vendor', 'N/A')}/{selected.get('product', 'N/A')}")
        
        if selected.get('severity'):
            print(f"Severity:          {selected['severity']}")
        
        print(f"Has Context:       {'Yes' if selected.get('has_context_snapshot') else 'No'}")
        print(f"Has Enrichment:    {'Yes' if selected.get('has_enrichment') else 'No'}")
        
        if selected.get('queue_created'):
            print(f"Queue Created:     {selected['queue_created']}")
        
        print("\nSelection Reasoning:")
        for reason in selector.selection_reasoning:
            print(f"  - {reason}")
        
        # Display SQL proof
        print(f"\nSQL Proof - CVE {selected['cve_id']}:")
        print("-" * 80)
        sql_proof = selector.get_sql_proof(selected['cve_id'])
        if sql_proof:
            print(f"Has Approved Playbook: {sql_proof.get('has_approved_playbook', 'N/A')}")
            print(f"Queue Status:          {sql_proof.get('queue_status', 'N/A')}")
            print(f"Queue Priority:        {sql_proof.get('queue_priority', 'N/A')}")
            print(f"Latest Gen Status:     {sql_proof.get('latest_generation_status', 'N/A')}")
            print(f"Has Context:           {sql_proof.get('has_context', 'N/A')}")
            print(f"Is Test CVE:           {sql_proof.get('is_test', 'N/A')}")
            
            # Verification summary
            print(f"\nVerification Summary:")
            if sql_proof.get('has_approved_playbook'):
                print("  X FAIL: CVE already has approved playbook")
            else:
                print("  PASS: CVE does not have approved playbook")
            
            if sql_proof.get('queue_status') in ['completed', 'archived']:
                print("  X FAIL: CVE queue status is completed/archived")
            else:
                print("  PASS: CVE queue status is eligible")
            
            if sql_proof.get('is_test') and not args.allow_test_cves:
                print("  X FAIL: CVE is a test CVE (use --allow-test-cves)")
            else:
                print("  PASS: CVE is not a test CVE or test CVEs allowed")
        else:
            print("  No SQL proof available")
        
        if args.verbose and selector.candidates:
            print(f"\nRanked Candidates ({len(selector.candidates)} total):")
            print("-" * 80)
            for i, candidate in enumerate(selector.candidates[:10], 1):
                if "selection_score" in candidate:
                    score = candidate["selection_score"]
                    status = "Yes" if candidate.get("has_context_snapshot") else "No"
                    print(f"{i:2}. {candidate['cve_id']:20} | Score: {score:.2f} | Context: {status} | {candidate.get('queue_status', 'N/A')}")
            
            if len(selector.candidates) > 10:
                print(f"... and {len(selector.candidates) - 10} more")
        
        print("\n" + "=" * 80)
    
    # Exit with appropriate code
    if not selected:
        sys.exit(1)
    sys.exit(0)


# -----------------------------------------------------------------------------

if __name__ == "__main__":
    main()