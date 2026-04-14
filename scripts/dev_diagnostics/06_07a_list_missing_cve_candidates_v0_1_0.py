#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Service: VS.ai Playbook Engine
Script: List Missing CVE Candidates
File: 06_07a_list_missing_cve_candidates_v0_1_0.py
Version: v0.1.0
Timestamp (UTC): 2026-04-08

Purpose:
    List CVEs that do NOT have approved playbooks.
    Filter criteria:
    - present in cve_queue
    - NOT in approved_playbooks
    - NOT completed
    - NOT currently processing
    - optionally exclude most recent CVE
    - prefer CVEs with enrichment/context

Usage:
    python scripts/06_07a_list_missing_cve_candidates_v0_1_0.py [--exclude-recent] [--json]
"""

import argparse
import json
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Sequence

# Adjust path if needed depending on your repo layout
sys.path.append(".")

from src.utils.db import DatabaseClient


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def get_missing_cve_candidates(db: DatabaseClient, exclude_recent: bool = False, allow_test_cves: bool = False) -> Sequence[Dict[str, Any]]:
    """
    Get CVEs missing approved playbooks with eligibility criteria.
    
    Args:
        db: Database client
        exclude_recent: Whether to exclude the most recently processed CVE
        allow_test_cves: Whether to include test CVEs (CVE-TEST-*)
        
    Returns:
        List of candidate CVEs with eligibility information
    """
    # Get the most recently processed CVE if excluding recent
    last_processed_cve = None
    if exclude_recent:
        last_query = """
        SELECT cve_id
        FROM generation_runs
        WHERE created_at IS NOT NULL
        ORDER BY created_at DESC
        LIMIT 1
        """
        result = db.fetch_one(last_query)
        if result:
            last_processed_cve = result["cve_id"]
    
    # Build WHERE clause for test CVE filtering
    test_cve_filter = ""
    if not allow_test_cves:
        test_cve_filter = """
        -- Exclude test CVEs (CVE-TEST-*, TEST-*, synthetic fixtures)
        AND q.cve_id NOT LIKE 'CVE-TEST-%'
        AND q.cve_id NOT LIKE 'TEST-%'
        AND q.cve_id NOT LIKE 'DEMO-%'
        AND q.cve_id NOT LIKE 'SYNTHETIC-%'
        AND q.cve_id NOT LIKE 'SEEDED-%'
        """
    
    # Main query to find missing CVE candidates
    query = f"""
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
    )
    SELECT 
        q.cve_id,
        q.status as queue_status,
        q.priority,
        q.created_at as queue_created,
        q.updated_at as queue_updated,
        -- Check if CVE has approved playbook
        CASE WHEN ac.cve_id IS NOT NULL THEN TRUE ELSE FALSE END as has_approved_playbook,
        -- Check if CVE has generation run
        CASE WHEN gr.id IS NOT NULL THEN TRUE ELSE FALSE END as has_generation_run,
        -- Check if CVE has context snapshot
        CASE WHEN ccs.cve_id IS NOT NULL THEN TRUE ELSE FALSE END as has_context_snapshot,
        -- Check if CVE is currently being processed
        CASE WHEN pc.cve_id IS NOT NULL THEN TRUE ELSE FALSE END as is_processing,
        -- Get latest generation status if exists
        gr.status as latest_generation_status,
        gr.created_at as latest_generation_date,
        -- Get vendor/product from context if available
        NULL as vendor,
        NULL as product,
        NULL as severity,
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
    WHERE 
        -- Only CVEs in queue
        q.cve_id IS NOT NULL
        -- Not completed
        AND q.status NOT IN ('completed', 'archived')
        -- Not already approved
        AND ac.cve_id IS NULL
        -- Not currently processing (optional, could be retry)
        AND (pc.cve_id IS NULL OR q.status = 'failed')
        {test_cve_filter}
    ORDER BY 
        -- Prefer CVEs with context
        CASE WHEN ccs.cve_id IS NOT NULL THEN 0 ELSE 1 END,
        -- Higher priority first
        q.priority DESC,
        -- Older queue items first
        q.created_at ASC
    """
    
    candidates = db.fetch_all(query)
    
    # Add eligibility and notes
    for candidate in candidates:
        candidate["eligible_for_selection"] = determine_eligibility(candidate, allow_test_cves)
        candidate["notes"] = generate_notes(candidate)
        
        # Add exclusion flag if this is the most recent CVE
        if exclude_recent and candidate["cve_id"] == last_processed_cve:
            candidate["exclude_as_recent"] = True
        else:
            candidate["exclude_as_recent"] = False
    
    return candidates


def determine_eligibility(candidate: Dict[str, Any], allow_test_cves: bool = False) -> bool:
    """Determine if CVE is eligible for selection."""
    # Must not have approved playbook
    if candidate.get("has_approved_playbook"):
        return False
    
    # Must not be a test CVE unless explicitly allowed
    if candidate.get("is_test_cve") and not allow_test_cves:
        return False
    
    # Must not be currently processing (unless failed and retry eligible)
    if candidate.get("is_processing") and candidate.get("queue_status") != "failed":
        return False
    
    # Queue status must be eligible
    queue_status = candidate.get("queue_status", "")
    if queue_status in ["completed", "archived"]:
        return False
    
    # If has generation run, check status
    if candidate.get("has_generation_run"):
        gen_status = candidate.get("latest_generation_status", "")
        if gen_status in ["completed", "approved"]:
            return False
    
    return True


def generate_notes(candidate: Dict[str, Any]) -> str:
    """Generate human-readable notes about candidate."""
    notes = []
    
    if candidate.get("is_test_cve"):
        notes.append("TEST CVE")
    
    if candidate.get("has_approved_playbook"):
        notes.append("Has approved playbook")
    
    if candidate.get("is_processing"):
        notes.append("Currently processing")
    
    if candidate.get("has_context_snapshot"):
        notes.append("Has context snapshot")
    else:
        notes.append("Missing context - needs enrichment")
    
    if candidate.get("queue_status") == "failed":
        notes.append("Previous processing failed")
    
    if candidate.get("latest_generation_status"):
        notes.append(f"Last generation: {candidate['latest_generation_status']}")
    
    return "; ".join(notes)


def print_candidates_table(candidates: Sequence[Dict[str, Any]]):
    """Print candidates in formatted table."""
    if not candidates:
        print("No missing CVE candidates found.")
        return
    
    print("\n" + "=" * 120)
    print("MISSING CVE CANDIDATES")
    print("=" * 120)
    print(f"{'CVE ID':20} {'Test':4} {'Queue Status':12} {'Priority':8} {'Context':7} {'Eligible':8} {'Vendor/Product':30} {'Notes'}")
    print("-" * 120)
    
    for candidate in candidates:
        cve_id = candidate["cve_id"]
        is_test = "T" if candidate.get("is_test_cve") else ""
        queue_status = candidate["queue_status"]
        priority = candidate["priority"]
        has_context = "Yes" if candidate["has_context_snapshot"] else "No"
        eligible = "Yes" if candidate["eligible_for_selection"] else "No"
        
        # Truncate vendor/product for display
        vendor = candidate.get("vendor", "") or ""
        product = candidate.get("product", "") or ""
        vendor_product = f"{vendor}/{product}"[:28]
        
        notes = candidate["notes"][:40] + "..." if len(candidate["notes"]) > 40 else candidate["notes"]
        
        print(f"{cve_id:20} {is_test:4} {queue_status:12} {priority:8} {has_context:7} {eligible:8} {vendor_product:30} {notes}")
    
    print("=" * 120)
    print(f"Total candidates: {len(candidates)}")
    
    # Count eligible candidates
    eligible_count = sum(1 for c in candidates if c["eligible_for_selection"])
    print(f"Eligible for selection: {eligible_count}")
    
    # Count with context
    context_count = sum(1 for c in candidates if c["has_context_snapshot"])
    print(f"With context snapshot: {context_count}")


def print_detailed_candidate(candidate: Dict[str, Any]):
    """Print detailed information for a single candidate."""
    print("\n" + "=" * 80)
    print(f"CANDIDATE DETAIL: {candidate['cve_id']}")
    print("=" * 80)
    
    print(f"CVE ID:               {candidate['cve_id']}")
    print(f"Is Test CVE:          {candidate.get('is_test_cve', False)}")
    print(f"Queue Status:         {candidate['queue_status']}")
    print(f"Priority:             {candidate['priority']}")
    print(f"Queue Created:        {candidate['queue_created']}")
    print(f"Queue Updated:        {candidate['queue_updated']}")
    print(f"Has Approved Playbook: {candidate['has_approved_playbook']}")
    print(f"Has Generation Run:   {candidate['has_generation_run']}")
    print(f"Has Context Snapshot: {candidate['has_context_snapshot']}")
    print(f"Is Processing:        {candidate['is_processing']}")
    print(f"Eligible for Selection: {candidate['eligible_for_selection']}")
    
    if candidate.get('vendor') or candidate.get('product'):
        print(f"Vendor:               {candidate.get('vendor', 'N/A')}")
        print(f"Product:              {candidate.get('product', 'N/A')}")
    
    if candidate.get('severity'):
        print(f"Severity:             {candidate['severity']}")
    
    if candidate.get('latest_generation_status'):
        print(f"Latest Gen Status:    {candidate['latest_generation_status']}")
        print(f"Latest Gen Date:      {candidate['latest_generation_date']}")
    
    print(f"\nNotes: {candidate['notes']}")
    print("=" * 80)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exclude-recent", action="store_true", 
                       help="Exclude the most recently processed CVE")
    parser.add_argument("--allow-test-cves", action="store_true", 
                       help="Allow test CVEs (CVE-TEST-*, TEST-*, etc.)")
    parser.add_argument("--json", action="store_true", 
                       help="Output JSON format")
    parser.add_argument("--detailed", action="store_true",
                       help="Show detailed information for each candidate")
    parser.add_argument("--limit", type=int, default=0,
                       help="Limit number of candidates shown (0 for all)")
    args = parser.parse_args()
    
    print("=" * 80)
    print(f"[MISSING CVE CANDIDATES] Listing candidates (exclude_recent: {args.exclude_recent}, allow_test_cves: {args.allow_test_cves})")
    print("=" * 80)
    
    db = DatabaseClient()
    
    # Get candidates
    candidates = get_missing_cve_candidates(db, args.exclude_recent, args.allow_test_cves)
    
    # Apply limit if specified
    if args.limit > 0:
        candidates = candidates[:args.limit]
    
    if args.json:
        # Output JSON format
        output = {
            "timestamp": datetime.utcnow().isoformat(),
            "exclude_recent": args.exclude_recent,
            "allow_test_cves": args.allow_test_cves,
            "total_candidates": len(candidates),
            "candidates": candidates
        }
        print(json.dumps(output, indent=2, default=str))
    elif args.detailed:
        # Print detailed information for each candidate
        for i, candidate in enumerate(candidates, 1):
            print_detailed_candidate(candidate)
            if i < len(candidates):
                print("\n")
    else:
        # Print table format
        print_candidates_table(candidates)
    
    # Exit with appropriate code
    if not candidates:
        print("\n[ERROR] No eligible candidates found")
        sys.exit(1)
    
    eligible_count = sum(1 for c in candidates if c["eligible_for_selection"])
    if eligible_count == 0:
        print("\n⚠️  Candidates found but none are eligible")
        sys.exit(2)
    
        print(f"\n[SUCCESS] Found {len(candidates)} candidates ({eligible_count} eligible)")
    sys.exit(0)


# -----------------------------------------------------------------------------

if __name__ == "__main__":
    main()