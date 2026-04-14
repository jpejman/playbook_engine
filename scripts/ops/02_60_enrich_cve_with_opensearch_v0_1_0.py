#!/usr/bin/env python3
"""
Playbook Engine - CVE OpenSearch Enrichment Script
Version: v0.1.0
Timestamp: 2026-04-08

Purpose:
- Enrich CVE with OpenSearch evidence
- Exact CVE lookup in OpenSearch
- Fallback keyword retrieval if exact match is poor
- Normalize returned documents
- Classify enrichment quality (empty/weak/sufficient)
- Output structured enrichment package

Design Rules:
- Enrichment is separate from generation
- No generation logic in this script
- Output structured JSON for downstream consumption
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.retrieval.opensearch_client import get_real_opensearch_client

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CVEOpenSearchEnricher:
    """Enrich CVE with OpenSearch evidence."""
    
    def __init__(self, cve_id: str):
        self.cve_id = cve_id
        self.opensearch_client = get_real_opensearch_client()
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "cve_id": cve_id,
            "enrichment_decision": "empty",
            "hit_count": 0,
            "source_indexes": [],
            "documents": [],
            "quality_metrics": {}
        }
        
        logger.info(f"CVEOpenSearchEnricher initialized for {cve_id}")
    
    def enrich_cve(self) -> Dict[str, Any]:
        """
        Enrich CVE with OpenSearch evidence.
        
        Returns:
            Enrichment results package
        """
        logger.info(f"Enriching CVE {self.cve_id} with OpenSearch...")
        
        # Step 1: Try exact CVE match
        exact_matches = self._search_exact_cve()
        
        # Step 2: If exact matches are poor, try keyword search
        if self._is_poor_exact_match(exact_matches):
            logger.info(f"Exact match quality is poor, trying keyword search...")
            keyword_matches = self._search_keyword()
            
            # Combine matches (deduplicate)
            all_matches = self._combine_and_deduplicate(exact_matches, keyword_matches)
        else:
            all_matches = exact_matches
        
        # Step 3: Normalize documents
        normalized_docs = self._normalize_documents(all_matches)
        
        # Step 4: Calculate quality metrics
        quality_metrics = self._calculate_quality_metrics(normalized_docs)
        
        # Step 5: Make enrichment decision
        enrichment_decision = self._make_enrichment_decision(quality_metrics, normalized_docs)
        
        # Step 6: Build results package
        self.results.update({
            "enrichment_decision": enrichment_decision,
            "hit_count": len(normalized_docs),
            "source_indexes": list(set(doc.get('source_index', 'unknown') for doc in normalized_docs)),
            "documents": normalized_docs,
            "quality_metrics": quality_metrics
        })
        
        logger.info(f"Enrichment complete: {len(normalized_docs)} documents, decision: {enrichment_decision}")
        return self.results
    
    def _search_exact_cve(self) -> List[Dict[str, Any]]:
        """Search for exact CVE matches in OpenSearch."""
        logger.info(f"Searching for exact CVE match: {self.cve_id}")
        
        try:
            matches = self.opensearch_client.search_cve_exact(self.cve_id)
            logger.info(f"Found {len(matches)} exact CVE matches")
            return matches
        except Exception as e:
            logger.error(f"Exact CVE search failed: {e}")
            return []
    
    def _search_keyword(self) -> List[Dict[str, Any]]:
        """Search for keyword matches in OpenSearch."""
        logger.info(f"Searching for keyword matches related to {self.cve_id}")
        
        try:
            # Use CVE ID as keyword (strip "CVE-" prefix for broader search)
            keyword = self.cve_id.replace("CVE-", "")
            matches = self.opensearch_client.search_keyword(keyword)
            logger.info(f"Found {len(matches)} keyword matches")
            return matches
        except Exception as e:
            logger.error(f"Keyword search failed: {e}")
            return []
    
    def _is_poor_exact_match(self, exact_matches: List[Dict[str, Any]]) -> bool:
        """
        Determine if exact match results are poor.
        
        Criteria:
        - Fewer than 2 matches
        - Low average score (< 5.0)
        - High duplicate ratio
        """
        if len(exact_matches) < 2:
            logger.info(f"Exact match is poor: only {len(exact_matches)} matches")
            return True
        
        # Calculate average score
        scores = [match.get('score', 0) for match in exact_matches]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        if avg_score < 5.0:
            logger.info(f"Exact match is poor: low average score ({avg_score:.2f})")
            return True
        
        # Check for duplicates
        duplicate_ratio = self._calculate_duplicate_ratio(exact_matches)
        if duplicate_ratio > 0.5:
            logger.info(f"Exact match is poor: high duplicate ratio ({duplicate_ratio:.2f})")
            return True
        
        return False
    
    def _calculate_duplicate_ratio(self, documents: List[Dict[str, Any]]) -> float:
        """Calculate duplicate ratio in documents."""
        if len(documents) <= 1:
            return 0.0
        
        # Simple duplicate detection by content hash
        content_hashes = set()
        duplicate_count = 0
        
        for doc in documents:
            content = doc.get('content', '').strip()
            if not content:
                continue
            
            # Create simple hash (first 200 chars)
            content_hash = hash(content[:200])
            if content_hash in content_hashes:
                duplicate_count += 1
            else:
                content_hashes.add(content_hash)
        
        return duplicate_count / len(documents) if documents else 0.0
    
    def _combine_and_deduplicate(self, list1: List[Dict[str, Any]], 
                                list2: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Combine and deduplicate document lists."""
        combined = list1.copy()
        
        # Track doc_ids from first list
        existing_ids = {doc.get('doc_id', '') for doc in list1}
        
        # Add documents from second list if not already present
        for doc in list2:
            doc_id = doc.get('doc_id', '')
            if doc_id and doc_id not in existing_ids:
                combined.append(doc)
                existing_ids.add(doc_id)
        
        # Sort by score descending
        combined.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        logger.info(f"Combined {len(list1)} + {len(list2)} -> {len(combined)} unique documents")
        return combined
    
    def _normalize_documents(self, documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize documents to standard format."""
        normalized = []
        
        for i, doc in enumerate(documents):
            try:
                normalized_doc = {
                    "doc_id": doc.get('doc_id', f'doc-{i}'),
                    "source_index": doc.get('source_index', 'unknown'),
                    "score": float(doc.get('score', 0.0)),
                    "title": doc.get('title', '')[:200],
                    "content": doc.get('content', '')[:1000],
                    "metadata": doc.get('metadata', {})
                }
                
                # Ensure metadata has required fields
                if 'metadata' not in normalized_doc or not normalized_doc['metadata']:
                    normalized_doc['metadata'] = {}
                
                metadata = normalized_doc['metadata']
                metadata.update({
                    "source_index": normalized_doc['source_index'],
                    "title": normalized_doc['title'],
                    "retrieval_source": metadata.get('retrieval_source', 'opensearch'),
                    "cve_id": self.cve_id
                })
                
                normalized.append(normalized_doc)
                
            except Exception as e:
                logger.warning(f"Failed to normalize document {i}: {e}")
                continue
        
        logger.info(f"Normalized {len(normalized)}/{len(documents)} documents")
        return normalized
    
    def _calculate_quality_metrics(self, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate quality metrics for enrichment."""
        if not documents:
            return {
                "document_count": 0,
                "average_score": 0.0,
                "duplicate_ratio": 0.0,
                "source_diversity": 0,
                "placeholder_count": 0
            }
        
        # Basic metrics
        document_count = len(documents)
        scores = [doc.get('score', 0) for doc in documents]
        average_score = sum(scores) / len(scores) if scores else 0.0
        
        # Duplicate ratio
        duplicate_ratio = self._calculate_duplicate_ratio(documents)
        
        # Source diversity
        source_indexes = set(doc.get('source_index', 'unknown') for doc in documents)
        source_diversity = len(source_indexes)
        
        # Placeholder count
        placeholder_count = 0
        placeholder_phrases = [
            "test vulnerability context",
            "placeholder",
            "mock data",
            "sample content",
            "dummy text"
        ]
        
        for doc in documents:
            content = doc.get('content', '').lower()
            title = doc.get('title', '').lower()
            
            for phrase in placeholder_phrases:
                if phrase in content or phrase in title:
                    placeholder_count += 1
                    break
        
        metrics = {
            "document_count": document_count,
            "average_score": round(average_score, 2),
            "duplicate_ratio": round(duplicate_ratio, 3),
            "source_diversity": source_diversity,
            "placeholder_count": placeholder_count,
            "placeholder_ratio": round(placeholder_count / document_count, 3) if document_count > 0 else 0.0
        }
        
        logger.info(f"Quality metrics: {metrics}")
        return metrics
    
    def _make_enrichment_decision(self, quality_metrics: Dict[str, Any], 
                                 documents: List[Dict[str, Any]]) -> str:
        """
        Make enrichment quality decision.
        
        Returns:
            "empty", "weak", or "sufficient"
        """
        document_count = quality_metrics['document_count']
        duplicate_ratio = quality_metrics['duplicate_ratio']
        source_diversity = quality_metrics['source_diversity']
        placeholder_ratio = quality_metrics['placeholder_ratio']
        
        # Empty decision
        if document_count == 0:
            logger.warning("Enrichment decision: EMPTY - no documents found")
            return "empty"
        
        # Weak decision criteria
        if document_count < 3:
            logger.warning(f"Enrichment decision: WEAK - insufficient documents ({document_count})")
            return "weak"
        
        if duplicate_ratio > 0.6:
            logger.warning(f"Enrichment decision: WEAK - high duplicate ratio ({duplicate_ratio:.2f})")
            return "weak"
        
        if source_diversity < 2:
            logger.warning(f"Enrichment decision: WEAK - low source diversity ({source_diversity})")
            return "weak"
        
        if placeholder_ratio > 0.3:
            logger.warning(f"Enrichment decision: WEAK - high placeholder ratio ({placeholder_ratio:.2f})")
            return "weak"
        
        # Sufficient decision
        logger.info("Enrichment decision: SUFFICIENT - good quality evidence")
        return "sufficient"
    
    def print_results(self, output_json: Optional[str] = None):
        """Print enrichment results."""
        decision = self.results["enrichment_decision"]
        hit_count = self.results["hit_count"]
        source_indexes = self.results["source_indexes"]
        
        print("\n" + "=" * 80)
        print("CVE OPENSEARCH ENRICHMENT RESULTS")
        print("=" * 80)
        print(f"CVE ID: {self.cve_id}")
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Enrichment Decision: {decision}")
        print(f"Hit Count: {hit_count}")
        print(f"Source Indexes: {', '.join(source_indexes) if source_indexes else 'None'}")
        print("-" * 80)
        
        # Print quality metrics
        metrics = self.results["quality_metrics"]
        print("\nQuality Metrics:")
        for key, value in metrics.items():
            print(f"  {key}: {value}")
        
        # Print document summary
        documents = self.results["documents"]
        if documents:
            print(f"\nTop Documents ({min(3, len(documents))} of {len(documents)}):")
            for i, doc in enumerate(documents[:3], 1):
                print(f"\n{i}. {doc.get('source_index', 'unknown')} - Score: {doc.get('score', 0):.2f}")
                title = doc.get('title', 'No title')
                if len(title) > 80:
                    title = title[:77] + "..."
                print(f"   Title: {title}")
                
                content = doc.get('content', '')
                if content and len(content) > 120:
                    content = content[:117] + "..."
                print(f"   Content: {content}")
        else:
            print("\nNo documents found")
        
        print("=" * 80)
        
        # Save to JSON if requested
        if output_json:
            output_path = Path(output_json)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert documents to serializable format
            serializable_results = self.results.copy()
            # Ensure all values are JSON serializable
            import json
            def default_serializer(obj):
                if isinstance(obj, (datetime,)):
                    return obj.isoformat()
                raise TypeError(f"Type {type(obj)} not serializable")
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(serializable_results, f, indent=2, default=default_serializer)
            
            logger.info(f"Results saved to {output_path}")
            print(f"\nJSON output saved to: {output_path}")
    
    def run_enrichment(self, output_json: Optional[str] = None) -> bool:
        """Run complete enrichment workflow."""
        logger.info("CVE OPENSEARCH ENRICHMENT")
        logger.info("=" * 60)
        
        try:
            # Run enrichment
            results = self.enrich_cve()
            
            # Print results
            self.print_results(output_json)
            
            # Return success status
            success = results["enrichment_decision"] != "empty"
            if success:
                logger.info(f"Enrichment successful: {results['hit_count']} documents, decision: {results['enrichment_decision']}")
            else:
                logger.warning("Enrichment completed but found no documents")
            
            return success
            
        except Exception as e:
            logger.error(f"Enrichment failed: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Enrich CVE with OpenSearch evidence')
    parser.add_argument('--cve', type=str, required=True,
                       help='CVE ID to enrich (e.g., CVE-2025-12345)')
    parser.add_argument('--output-json', type=str,
                       help='Save results to JSON file')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run enrichment
    enricher = CVEOpenSearchEnricher(args.cve)
    success = enricher.run_enrichment(
        output_json=args.output_json
    )
    
    if success:
        logger.info("\nEnrichment completed successfully")
        sys.exit(0)
    else:
        logger.error("\nEnrichment failed or found no evidence")
        sys.exit(1)


if __name__ == "__main__":
    main()