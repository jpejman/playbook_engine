"""
OpenSearch Intake
Version: v0.1.0
Timestamp (UTC): 2026-04-14
"""

from typing import List, Dict
from src.retrieval.opensearch_client import RealOpenSearchClient


class OpenSearchIntakeService:

    def __init__(self):
        self.client = RealOpenSearchClient().client

    def fetch_candidates(self, limit=100) -> List[Dict]:
        query = {
            "size": limit,
            "sort": [{"published": {"order": "desc"}}],
            "query": {"match_all": {}}
        }

        res = self.client.search(index="cve", body=query)
        hits = res.get("hits", {}).get("hits", [])

        candidates = []
        for h in hits:
            source = h["_source"]
            candidates.append({
                "cve_id": source.get("id"),
                "published": source.get("published"),
                "metrics": source.get("metrics", {})
            })

        return candidates