#!/usr/bin/env python3
"""
Evidence Collector for Playbook Engine
Version: v0.2.1-fix
Timestamp: 2026-04-08

Purpose:
- Collect all prompt-generation inputs before LLM execution
- Query real evidence from OpenSearch and PostgreSQL vulnstrike DB
- Normalize and aggregate evidence
- Make retrieval sufficiency decision
- Persist aggregated retrieval state
"""

import os
import json
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

from .opensearch_client import get_real_opensearch_client
from .vulnstrike_db_client import get_vulnstrike_db_client

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EvidenceCollector:
    """
    Collects and aggregates evidence from multiple sources.
    
    Responsibilities:
    1. Queue item / target CVE
    2. Context snapshot from playbook_engine
    3. Active prompt template / version
    4. OpenSearch evidence
    5. Vulnstrike DB evidence
    6. Normalized evidence list
    7. Retrieval sufficiency decision
    """
    
    def __init__(self, cve_id: str, context_snapshot: Dict[str, Any]):
        """
        Initialize evidence collector.
        
        Args:
            cve_id: Target CVE identifier
            context_snapshot: Context data from playbook_engine
        """
        self.cve_id = cve_id
        self.context_snapshot = context_snapshot
        self.opensearch_client = get_real_opensearch_client()
        self.vulnstrike_client = get_vulnstrike_db_client()
        
        # Collected evidence
        self.opensearch_evidence: List[Dict[str, Any]] = []
        self.vulnstrike_evidence: List[Dict[str, Any]] = []
        self.all_evidence: List[Dict[str, Any]] = []
        
        # Decision state
        self.retrieval_decision: str = "empty"
        self.source_indexes: List[str] = []
        self.evidence_count: int = 0
        
        # Timing metrics
        self.timing_metrics: Dict[str, float] = {}
        
        # Query inputs
        self.query_inputs = self._build_query_inputs()
        
        logger.info(f"EvidenceCollector initialized for {cve_id}")
    
    def _build_query_inputs(self) -> Dict[str, Any]:
        """Build query inputs from CVE context."""
        return {
            "cve_id": self.cve_id,
            "description": self.context_snapshot.get("description", ""),
            "cwe": self.context_snapshot.get("cwe", ""),
            "affected_products": self.context_snapshot.get("affected_products", []),
            "vulnerability_type": self.context_snapshot.get("vulnerability_type", ""),
            "attack_vector": self.context_snapshot.get("attack_vector", ""),
            "cvss_score": self.context_snapshot.get("cvss_score", 0)
        }
    
    def collect_all_evidence(self) -> Dict[str, Any]:
        """
        Collect evidence from all sources.
        
        Returns:
            Aggregated evidence package
        """
        logger.info(f"Collecting evidence for {self.cve_id}")
        evidence_start_time = time.time()
        
        # Step 1: Collect from OpenSearch
        opensearch_start = time.time()
        self._collect_opensearch_evidence()
        self.timing_metrics['opensearch_retrieval_time_seconds'] = time.time() - opensearch_start
        
        # Step 2: Collect from Vulnstrike DB
        postgres_start = time.time()
        self._collect_vulnstrike_evidence()
        self.timing_metrics['postgres_retrieval_time_seconds'] = time.time() - postgres_start
        
        # Step 3: Aggregate all evidence
        aggregate_start = time.time()
        self._aggregate_evidence()
        self.timing_metrics['evidence_aggregation_time_seconds'] = time.time() - aggregate_start
        
        # Step 4: Make retrieval decision
        decision_start = time.time()
        self._make_retrieval_decision()
        self.timing_metrics['retrieval_decision_time_seconds'] = time.time() - decision_start
        
        # Step 5: Build aggregated package
        package_start = time.time()
        aggregated_package = self._build_aggregated_package()
        self.timing_metrics['package_build_time_seconds'] = time.time() - package_start
        
        # Total evidence collection time
        self.timing_metrics['evidence_collection_time_seconds'] = time.time() - evidence_start_time
        
        # Log timing metrics
        logger.info(f"Evidence collection complete: {self.evidence_count} items, decision: {self.retrieval_decision}")
        logger.info("Evidence collection timing breakdown:")
        for timing_name, timing_value in self.timing_metrics.items():
            logger.info(f"  {timing_name}: {timing_value:.2f} seconds")
        
        # Include timing metrics in aggregated package
        aggregated_package['timing_metrics'] = self.timing_metrics
        
        return aggregated_package
    
    def _collect_opensearch_evidence(self):
        """Collect evidence from OpenSearch."""
        logger.info("Collecting evidence from OpenSearch...")
        
        try:
            # Try exact CVE match first
            exact_matches = self.opensearch_client.search_cve_exact(self.cve_id)
            
            if exact_matches:
                logger.info(f"Found {len(exact_matches)} exact CVE matches in OpenSearch")
                self.opensearch_evidence.extend(exact_matches)
            
            # If no exact matches or we want more context, try hybrid search
            if len(self.opensearch_evidence) < 3:  # Want at least 3 good matches
                hybrid_matches = self.opensearch_client.search_hybrid(self.query_inputs)
                logger.info(f"Found {len(hybrid_matches)} hybrid matches in OpenSearch")
                
                # Filter out duplicates by doc_id
                existing_ids = {e['doc_id'] for e in self.opensearch_evidence}
                for match in hybrid_matches:
                    if match['doc_id'] not in existing_ids:
                        self.opensearch_evidence.append(match)
                        existing_ids.add(match['doc_id'])
            
            # If still insufficient, try keyword search
            if len(self.opensearch_evidence) < 2:
                keywords = f"{self.query_inputs['description']} {self.query_inputs['vulnerability_type']}"
                keyword_matches = self.opensearch_client.search_keyword(keywords)
                logger.info(f"Found {len(keyword_matches)} keyword matches in OpenSearch")
                
                existing_ids = {e['doc_id'] for e in self.opensearch_evidence}
                for match in keyword_matches:
                    if match['doc_id'] not in existing_ids:
                        self.opensearch_evidence.append(match)
                        existing_ids.add(match['doc_id'])
            
            logger.info(f"Total OpenSearch evidence: {len(self.opensearch_evidence)} items")
            
        except Exception as e:
            logger.error(f"Failed to collect OpenSearch evidence: {e}")
            # Continue with whatever evidence we have
    
    def _collect_vulnstrike_evidence(self):
        """Collect evidence from Vulnstrike database."""
        logger.info("Collecting evidence from Vulnstrike DB...")
        
        try:
            # Test connection first
            connection_start = time.time()
            if not self.vulnstrike_client.test_connection():
                logger.warning("Vulnstrike DB connection test failed")
                return
            connection_time = time.time() - connection_start
            
            # Assert we're connected to the right database
            assertion_start = time.time()
            self.vulnstrike_client.assert_database_target()
            assertion_time = time.time() - assertion_start
            
            # Search for CVE data
            search_start = time.time()
            vulnstrike_matches = self.vulnstrike_client.search_cve_data(self.cve_id)
            search_time = time.time() - search_start
            
            logger.info(f"Found {len(vulnstrike_matches)} matches in Vulnstrike DB")
            
            # Extract detailed timing breakdown if available
            db_timing_breakdown = {}
            if vulnstrike_matches and '_timing_breakdown' in vulnstrike_matches[0]:
                db_timing_breakdown = vulnstrike_matches[0].pop('_timing_breakdown')
                logger.info("PostgreSQL retrieval detailed timing breakdown:")
                for timing_name, timing_value in db_timing_breakdown.items():
                    logger.info(f"    {timing_name}: {timing_value:.3f}s")
            
            # Store sub-step timings
            self.timing_metrics['postgres_connection_time_seconds'] = connection_time
            self.timing_metrics['postgres_assertion_time_seconds'] = assertion_time
            self.timing_metrics['postgres_search_time_seconds'] = search_time
            
            # Add DB timing breakdown to metrics
            for timing_name, timing_value in db_timing_breakdown.items():
                self.timing_metrics[f'postgres_{timing_name}'] = timing_value
            
            self.vulnstrike_evidence.extend(vulnstrike_matches)
            
        except Exception as e:
            logger.error(f"Failed to collect Vulnstrike evidence: {e}")
            # Continue with whatever evidence we have
    
    def _aggregate_evidence(self):
        """Aggregate and normalize all evidence."""
        logger.info("Aggregating evidence from all sources...")
        
        # Combine all evidence
        all_raw_evidence = self.opensearch_evidence + self.vulnstrike_evidence
        
        # Sort by score descending
        all_raw_evidence.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        # Apply quality filters first
        quality_evidence = []
        for evidence in all_raw_evidence:
            if self._is_quality_evidence(evidence):
                quality_evidence.append(evidence)
        
        # Deduplicate by normalized content hash
        deduplicated_evidence = self._deduplicate_evidence(quality_evidence)
        
        # Limit to top 20 items after deduplication
        deduplicated_evidence = deduplicated_evidence[:20]
        
        # Filter out low-value internal sources
        filtered_evidence = self._filter_low_value_sources(deduplicated_evidence)
        
        self.all_evidence = filtered_evidence
        
        # Collect unique source indexes
        source_indexes_set = set()
        for evidence in self.all_evidence:
            source_index = evidence.get('source_index', 'unknown')
            source_indexes_set.add(source_index)
        
        self.source_indexes = list(source_indexes_set)
        self.evidence_count = len(self.all_evidence)
        
        logger.info(f"Aggregated {self.evidence_count} quality evidence items from {len(self.source_indexes)} sources")
        logger.info(f"Deduplication stats: {len(quality_evidence)} before, {len(deduplicated_evidence)} after dedup, {len(filtered_evidence)} after filtering")
    
    def _deduplicate_evidence(self, evidence_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate evidence by normalized content hash."""
        if not evidence_list:
            return []
        
        deduplicated = []
        seen_hashes = set()
        
        for evidence in evidence_list:
            # Create normalized content for hashing
            content = evidence.get('content', '').strip()
            if not content:
                # Skip empty content
                continue
            
            # Normalize: lowercase, remove extra whitespace, take first 500 chars
            normalized = content.lower()
            normalized = ' '.join(normalized.split())  # Remove extra whitespace
            normalized = normalized[:500]  # Use first 500 chars for hash
            
            # Create hash
            import hashlib
            content_hash = hashlib.md5(normalized.encode('utf-8')).hexdigest()
            
            # Also check for near-duplicates by checking if content is subset of already seen content
            is_duplicate = False
            if content_hash in seen_hashes:
                is_duplicate = True
            else:
                # Check if this content is a subset of already seen content (or vice versa)
                for seen_hash in seen_hashes:
                    # For simplicity, we'll just use the hash check for now
                    # More sophisticated near-duplicate detection could be added here
                    pass
            
            if not is_duplicate:
                seen_hashes.add(content_hash)
                deduplicated.append(evidence)
            else:
                logger.debug(f"Deduplicated evidence with hash: {content_hash[:8]}...")
        
        return deduplicated
    
    def _filter_low_value_sources(self, evidence_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter out low-value internal sources."""
        low_value_sources = [
            'vulnstrike.cve_queue',
            'vulnstrike.retrieval_runs',
            'vulnstrike.generation_runs',
            'vulnstrike.approved_playbooks',
            'vulnstrike.qa_runs',
            'playbook_engine.cve_queue',
            'playbook_engine.retrieval_runs',
            'playbook_engine.generation_runs',
            'playbook_engine.approved_playbooks',
            'playbook_engine.qa_runs'
        ]
        
        filtered = []
        for evidence in evidence_list:
            source_index = evidence.get('source_index', '').lower()
            
            # Check if source is low-value
            is_low_value = False
            for low_value_source in low_value_sources:
                if low_value_source in source_index:
                    is_low_value = True
                    logger.debug(f"Filtered out low-value source: {source_index}")
                    break
            
            if not is_low_value:
                filtered.append(evidence)
        
        return filtered
    
    def _is_quality_evidence(self, evidence: Dict[str, Any]) -> bool:
        """
        Determine if evidence is of sufficient quality.
        
        Args:
            evidence: Evidence item to evaluate
            
        Returns:
            True if evidence meets quality threshold
        """
        # Check for placeholder content
        content = evidence.get('content', '').lower()
        title = evidence.get('title', '').lower()
        
        # Reject obvious placeholder content
        placeholder_phrases = [
            "test vulnerability context",
            "placeholder",
            "mock data",
            "sample content",
            "dummy text"
        ]
        
        for phrase in placeholder_phrases:
            if phrase in content or phrase in title:
                logger.debug(f"Rejecting evidence with placeholder phrase: {phrase}")
                return False
        
        # Check for minimum content length
        if len(content.strip()) < 20:
            logger.debug(f"Rejecting evidence with insufficient content length: {len(content)}")
            return False
        
        # Check for reasonable score (if available)
        score = evidence.get('score', 0)
        if score < 0.1 and 'opensearch' in evidence.get('source_index', ''):
            logger.debug(f"Rejecting evidence with low score: {score}")
            return False
        
        return True
    
    def _make_retrieval_decision(self):
        """
        Make retrieval sufficiency decision.
        
        Allowed outputs:
        - sufficient: Real evidence exists from OpenSearch and/or vulnstrike
        - weak: Only placeholder or low-information evidence exists
        - empty: Zero evidence rows
        """
        logger.info("Making retrieval sufficiency decision...")
        
        if self.evidence_count == 0:
            self.retrieval_decision = "empty"
            logger.warning("Retrieval decision: EMPTY - no evidence found")
            return
        
        # Calculate metrics for decision
        duplicate_ratio = self._calculate_duplicate_ratio()
        source_diversity = len(self.source_indexes)
        placeholder_count = self._count_placeholders()
        usable_doc_count = self.evidence_count - placeholder_count
        
        logger.info(f"Decision metrics: docs={self.evidence_count}, usable={usable_doc_count}, "
                   f"duplicates={duplicate_ratio:.2f}, sources={source_diversity}, placeholders={placeholder_count}")
        
        # Decision logic
        if usable_doc_count == 0:
            self.retrieval_decision = "empty"
            logger.warning("Retrieval decision: EMPTY - zero usable documents")
        
        elif duplicate_ratio > 0.5:
            self.retrieval_decision = "weak"
            logger.warning(f"Retrieval decision: WEAK - high duplication ratio ({duplicate_ratio:.2f})")
        
        elif source_diversity < 2:
            self.retrieval_decision = "weak"
            logger.warning(f"Retrieval decision: WEAK - low source diversity ({source_diversity})")
        
        elif placeholder_count > self.evidence_count * 0.3:  # More than 30% placeholders
            self.retrieval_decision = "weak"
            logger.warning(f"Retrieval decision: WEAK - high placeholder ratio ({placeholder_count}/{self.evidence_count})")
        
        elif usable_doc_count >= 5 and duplicate_ratio < 0.3 and source_diversity >= 2:
            self.retrieval_decision = "sufficient"
            logger.info("Retrieval decision: SUFFICIENT - good evidence quality")
        
        elif usable_doc_count >= 3:
            self.retrieval_decision = "sufficient"
            logger.info("Retrieval decision: SUFFICIENT - minimum usable evidence met")
        
        else:
            self.retrieval_decision = "weak"
            logger.warning("Retrieval decision: WEAK - insufficient evidence quality")
    
    def _calculate_duplicate_ratio(self) -> float:
        """Calculate duplicate ratio in evidence."""
        if self.evidence_count <= 1:
            return 0.0
        
        # Simple duplicate detection by content similarity
        contents = []
        for evidence in self.all_evidence:
            content = evidence.get('content', '').strip()
            if content:
                contents.append(content[:200])  # Use first 200 chars for comparison
        
        # Count duplicates
        duplicate_count = 0
        seen = set()
        for content in contents:
            if content in seen:
                duplicate_count += 1
            else:
                seen.add(content)
        
        return duplicate_count / self.evidence_count if self.evidence_count > 0 else 0.0
    
    def _count_placeholders(self) -> int:
        """Count placeholder evidence items."""
        placeholder_count = 0
        placeholder_phrases = [
            "test vulnerability context",
            "placeholder",
            "mock data",
            "sample content",
            "dummy text",
            "test content",
            "example content"
        ]
        
        for evidence in self.all_evidence:
            content = evidence.get('content', '').lower()
            title = evidence.get('title', '').lower()
            
            for phrase in placeholder_phrases:
                if phrase in content or phrase in title:
                    placeholder_count += 1
                    break
        
        return placeholder_count
    
    def _build_aggregated_package(self) -> Dict[str, Any]:
        """
        Build aggregated evidence package for persistence.
        
        Returns:
            Aggregated package matching required structure
        """
        package = {
            "decision": self.retrieval_decision,
            "query_inputs": self.query_inputs,
            "evidence_count": self.evidence_count,
            "sources": self.source_indexes,
            "evidence": self.all_evidence,
            "collection_timestamp": datetime.now().isoformat(),
            "opensearch_count": len(self.opensearch_evidence),
            "vulnstrike_count": len(self.vulnstrike_evidence)
        }
        
        return package
    
    def get_retrieval_decision(self) -> str:
        """Get the retrieval sufficiency decision."""
        return self.retrieval_decision
    
    def get_evidence_count(self) -> int:
        """Get the total evidence count."""
        return self.evidence_count
    
    def get_source_indexes(self) -> List[str]:
        """Get the unique source indexes."""
        return self.source_indexes
    
    def get_all_evidence(self) -> List[Dict[str, Any]]:
        """Get all aggregated evidence."""
        return self.all_evidence
    
    def should_generate(self) -> bool:
        """
        Determine if generation should proceed.
        
        Returns:
            True if generation should proceed, False otherwise
        """
        # Hard block for empty retrieval
        if self.retrieval_decision == "empty":
            logger.error("Generation blocked: retrieval decision is EMPTY")
            return False
        
        # Allow generation for sufficient and weak (with warning)
        if self.retrieval_decision in ["sufficient", "weak"]:
            if self.retrieval_decision == "weak":
                logger.warning("Generation allowed with WEAK retrieval - output may be degraded")
            return True
        
        # Default to blocking
        logger.error(f"Generation blocked: unknown retrieval decision {self.retrieval_decision}")
        return False
    
    def close(self):
        """Close client connections."""
        try:
            self.opensearch_client.close()
        except Exception as e:
            logger.warning(f"Error closing OpenSearch client: {e}")
        
        # Vulnstrike client doesn't have persistent connections


# Convenience function for quick access
def collect_evidence(cve_id: str, context_snapshot: Dict[str, Any]) -> EvidenceCollector:
    """
    Factory function to create and run evidence collection.
    
    Args:
        cve_id: Target CVE identifier
        context_snapshot: Context data from playbook_engine
        
    Returns:
        EvidenceCollector instance with collected evidence
    """
    collector = EvidenceCollector(cve_id, context_snapshot)
    collector.collect_all_evidence()
    return collector