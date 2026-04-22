"""
Evidence Packager for Continuous Pipeline v0.2.0
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z

Purpose:
- Package evidence for prompt generation
- Simulate evidence collection similar to Phase 1 runner
- Provide evidence context for canonical prompt builder
"""

import json
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class EvidencePackager:
    """
    Evidence packager for continuous pipeline.
    
    Simulates evidence collection similar to Phase 1 runner's EvidenceCollector
    but simplified for the continuous pipeline context.
    """
    
    def __init__(self, db_client, opensearch_client):
        self.db = db_client
        self.os = opensearch_client
        logger.info("EvidencePackager initialized")
    
    def package_evidence(self, cve_id: str, cve_doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Package evidence for CVE.
        
        Args:
            cve_id: CVE identifier
            cve_doc: CVE document from OpenSearch
            
        Returns:
            Evidence package dictionary
        """
        logger.info(f"Packaging evidence for {cve_id}")
        
        # Create evidence items from CVE document
        evidence_items = self._create_evidence_items(cve_id, cve_doc)
        
        # Create evidence package
        evidence_package = {
            "cve_id": cve_id,
            "retrieved_evidence": evidence_items,
            "evidence": evidence_items,  # Legacy compatibility
            "source_indexes": ["opensearch_nvd"],
            "evidence_count": len(evidence_items),
            "retrieval_decision": self._make_retrieval_decision(evidence_items),
            "retrieval_quality": self._assess_retrieval_quality(evidence_items)
        }
        
        logger.info(f"Evidence packaged: {len(evidence_items)} items, decision: {evidence_package['retrieval_decision']}")
        return evidence_package
    
    def _create_evidence_items(self, cve_id: str, cve_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create evidence items from CVE document."""
        evidence_items = []
        
        # Main CVE document as evidence
        main_evidence = {
            "doc_id": f"{cve_id}_main",
            "title": f"CVE-{cve_id} NVD Entry",
            "source_index": "opensearch_nvd",
            "content": self._format_cve_content(cve_doc),
            "score": 1.0,
            "metadata": {
                "source": "NVD",
                "cve_id": cve_id,
                "published_date": cve_doc.get("published_date", ""),
                "last_modified_date": cve_doc.get("last_modified_date", "")
            }
        }
        evidence_items.append(main_evidence)
        
        # Try to get additional evidence from database if available
        try:
            additional_evidence = self._get_additional_evidence(cve_id)
            if additional_evidence:
                evidence_items.extend(additional_evidence)
        except Exception as e:
            logger.warning(f"Failed to get additional evidence: {e}")
        
        return evidence_items
    
    def _format_cve_content(self, cve_doc: Dict[str, Any]) -> str:
        """Format CVE document as evidence content."""
        content_parts = []
        
        # Add basic info
        if cve_doc.get("description"):
            content_parts.append(f"Description: {cve_doc['description']}")
        
        if cve_doc.get("cvss_score"):
            content_parts.append(f"CVSS Score: {cve_doc['cvss_score']}")
        
        if cve_doc.get("severity"):
            content_parts.append(f"Severity: {cve_doc['severity']}")
        
        if cve_doc.get("cwe"):
            content_parts.append(f"CWE: {cve_doc['cwe']}")
        
        # Add affected components
        affected_info = []
        if cve_doc.get("vendor"):
            affected_info.append(f"Vendor: {cve_doc['vendor']}")
        if cve_doc.get("product"):
            affected_info.append(f"Product: {cve_doc['product']}")
        if cve_doc.get("affected_versions"):
            affected_info.append(f"Affected Versions: {cve_doc['affected_versions']}")
        
        if affected_info:
            content_parts.append("Affected Components: " + ", ".join(affected_info))
        
        # Add references (limited)
        references = cve_doc.get("references", [])
        if references:
            content_parts.append(f"References: {len(references)} available")
            for i, ref in enumerate(references[:3], 1):
                content_parts.append(f"  {i}. {ref}")
            if len(references) > 3:
                content_parts.append(f"  ... and {len(references) - 3} more")
        
        return "\n".join(content_parts)
    
    def _get_additional_evidence(self, cve_id: str) -> List[Dict[str, Any]]:
        """Get additional evidence from database if available."""
        additional_items = []
        
        # Check if there are existing retrieval documents for this CVE
        try:
            rows = self.db.fetch_all(
                """
                SELECT rd.content, rd.metadata_json, rd.score, rd.source
                FROM retrieval_documents rd
                JOIN retrieval_runs rr ON rd.retrieval_run_id = rr.id
                WHERE rr.cve_id = %s
                ORDER BY rd.score DESC
                LIMIT 3
                """,
                (cve_id,)
            )
            
            for i, row in enumerate(rows, 1):
                evidence_item = {
                    "doc_id": f"{cve_id}_db_{i}",
                    "title": f"Existing Evidence {i}",
                    "source_index": row.get("source", "database"),
                    "content": row.get("content", ""),
                    "score": float(row.get("score", 0.5)),
                    "metadata": json.loads(row.get("metadata_json", "{}")) if row.get("metadata_json") else {}
                }
                additional_items.append(evidence_item)
                
        except Exception as e:
            logger.debug(f"No existing retrieval documents found: {e}")
        
        return additional_items
    
    def _make_retrieval_decision(self, evidence_items: List[Dict[str, Any]]) -> str:
        """Make retrieval sufficiency decision."""
        if not evidence_items:
            return "empty"
        
        # Count evidence with good scores
        good_evidence = sum(1 for item in evidence_items if item.get("score", 0) >= 0.7)
        
        if good_evidence >= 2:
            return "sufficient"
        elif good_evidence >= 1:
            return "weak"
        else:
            return "empty"
    
    def _assess_retrieval_quality(self, evidence_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess retrieval quality."""
        quality = {
            "evidence_count": len(evidence_items),
            "average_score": 0.0,
            "max_score": 0.0,
            "source_diversity": 0,
            "has_opensearch_evidence": False,
            "has_database_evidence": False
        }
        
        if not evidence_items:
            return quality
        
        # Calculate scores
        total_score = 0.0
        valid_scores = 0
        sources = set()
        
        for item in evidence_items:
            score = item.get("score", 0)
            if score > 0:
                total_score += score
                valid_scores += 1
                quality["max_score"] = max(quality["max_score"], score)
            
            source = item.get("source_index", "")
            if source:
                sources.add(source)
                if "opensearch" in source.lower():
                    quality["has_opensearch_evidence"] = True
                elif "database" in source.lower() or "db" in source.lower():
                    quality["has_database_evidence"] = True
        
        if valid_scores > 0:
            quality["average_score"] = total_score / valid_scores
        
        quality["source_diversity"] = len(sources)
        
        return quality
    
    def persist_retrieval_run(self, cve_id: str, evidence_package: Dict[str, Any]) -> Optional[int]:
        """
        Persist retrieval run to database.
        
        Args:
            cve_id: CVE identifier
            evidence_package: Evidence package dictionary
            
        Returns:
            Retrieval run ID or None
        """
        try:
            # Insert retrieval run
            retrieval_run_id = self.db.insert_dynamic(
                "public.retrieval_runs",
                {
                    "cve_id": cve_id,
                    "status": "completed",
                    "source": "continuous_pipeline_v0_2_0",
                    "retrieved_context": json.dumps(evidence_package),
                    "source_indexes": evidence_package.get("source_indexes", []),
                    "created_at": "NOW()"
                },
                returning="id"
            )
            
            if retrieval_run_id and evidence_package.get("retrieved_evidence"):
                # Insert retrieval documents
                for i, item in enumerate(evidence_package["retrieved_evidence"], 1):
                    self.db.insert_dynamic(
                        "public.retrieval_documents",
                        {
                            "retrieval_run_id": retrieval_run_id,
                            "cve_id": cve_id,
                            "doc_id": item.get("doc_id", f"{cve_id}_doc_{i}"),
                            "content": item.get("content", ""),
                            "content_text": item.get("content", ""),
                            "metadata_json": json.dumps(item.get("metadata", {})),
                            "score": item.get("score", 0.5),
                            "rank": i,
                            "source": item.get("source_index", "unknown"),
                            "created_at": "NOW()"
                        }
                    )
            
            logger.info(f"Persisted retrieval run ID: {retrieval_run_id}")
            return retrieval_run_id
            
        except Exception as e:
            logger.error(f"Failed to persist retrieval run: {e}")
            return None