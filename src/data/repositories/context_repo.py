"""
Context Repository for CVE context snapshot operations.
"""

import logging
import json
import hashlib
from typing import Dict, List, Optional, Any

from utils.db import DatabaseClient

logger = logging.getLogger(__name__)


class ContextRepository:
    """Repository for CVE context snapshot operations."""
    
    def __init__(self, db_client: Optional[DatabaseClient] = None):
        self.db_client = db_client or DatabaseClient()
    
    def _generate_snapshot_hash(self, snapshot_json: Dict[str, Any]) -> str:
        """
        Generate hash for snapshot JSON.
        
        Args:
            snapshot_json: Snapshot JSON data
            
        Returns:
            SHA-256 hash string
        """
        # Sort keys for consistent hashing
        json_str = json.dumps(snapshot_json, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    def save_context_snapshot(
        self,
        cve_id: str,
        source: str,
        snapshot_json: Dict[str, Any]
    ) -> Optional[int]:
        """
        Save CVE context snapshot.
        
        Args:
            cve_id: CVE identifier
            source: Source of the context
            snapshot_json: Snapshot JSON data
            
        Returns:
            Snapshot ID or None if failed
        """
        snapshot_hash = self._generate_snapshot_hash(snapshot_json)
        
        sql = """
        INSERT INTO cve_context_snapshot (cve_id, source, snapshot_json, snapshot_hash)
        VALUES (%s, %s, %s::jsonb, %s)
        ON CONFLICT (cve_id, snapshot_hash) DO UPDATE SET
            source = EXCLUDED.source,
            snapshot_json = EXCLUDED.snapshot_json
        RETURNING id
        """
        
        try:
            result = self.db_client.fetch_one(sql, (
                cve_id,
                source,
                json.dumps(snapshot_json),
                snapshot_hash
            ))
            if result:
                logger.info(f"Saved context snapshot for CVE {cve_id}")
                return result['id']
        except Exception as e:
            logger.error(f"Failed to save context snapshot for CVE {cve_id}: {e}")
        
        return None
    
    def get_context_snapshot(self, snapshot_id: int) -> Optional[Dict[str, Any]]:
        """
        Get context snapshot by ID.
        
        Args:
            snapshot_id: Snapshot ID
            
        Returns:
            Context snapshot or None
        """
        sql = """
        SELECT 
            id, cve_id, source, snapshot_json, snapshot_hash, created_at
        FROM cve_context_snapshot
        WHERE id = %s
        """
        
        try:
            result = self.db_client.fetch_one(sql, (snapshot_id,))
            if result:
                # Parse JSON if needed
                if isinstance(result['snapshot_json'], str):
                    result['snapshot_json'] = json.loads(result['snapshot_json'])
                return result
        except Exception as e:
            logger.error(f"Failed to get context snapshot {snapshot_id}: {e}")
        
        return None
    
    def get_context_snapshots_by_cve(
        self,
        cve_id: str,
        limit: int = 10,
        source: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get context snapshots for a CVE.
        
        Args:
            cve_id: CVE identifier
            limit: Maximum number of snapshots to return
            source: Filter by source
            
        Returns:
            List of context snapshots
        """
        sql = """
        SELECT 
            id, source, snapshot_hash, created_at
        FROM cve_context_snapshot
        WHERE cve_id = %s
        """
        
        params = [cve_id]
        
        if source:
            sql += " AND source = %s"
            params.append(source)
        
        sql += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        
        try:
            return self.db_client.fetch_all(sql, tuple(params))
        except Exception as e:
            logger.error(f"Failed to get context snapshots for CVE {cve_id}: {e}")
            return []
    
    def get_latest_context_snapshot(
        self,
        cve_id: str,
        source: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get latest context snapshot for a CVE.
        
        Args:
            cve_id: CVE identifier
            source: Filter by source
            
        Returns:
            Latest context snapshot or None
        """
        sql = """
        SELECT 
            id, source, snapshot_json, snapshot_hash, created_at
        FROM cve_context_snapshot
        WHERE cve_id = %s
        """
        
        params = [cve_id]
        
        if source:
            sql += " AND source = %s"
            params.append(source)
        
        sql += " ORDER BY created_at DESC LIMIT 1"
        
        try:
            result = self.db_client.fetch_one(sql, tuple(params))
            if result:
                # Parse JSON if needed
                if isinstance(result['snapshot_json'], str):
                    result['snapshot_json'] = json.loads(result['snapshot_json'])
                return result
        except Exception as e:
            logger.error(f"Failed to get latest context snapshot for CVE {cve_id}: {e}")
        
        return None
    
    def check_snapshot_exists(self, cve_id: str, snapshot_hash: str) -> bool:
        """
        Check if a snapshot with given hash exists for a CVE.
        
        Args:
            cve_id: CVE identifier
            snapshot_hash: Snapshot hash
            
        Returns:
            True if snapshot exists
        """
        sql = """
        SELECT EXISTS(
            SELECT 1 FROM cve_context_snapshot
            WHERE cve_id = %s AND snapshot_hash = %s
        ) as exists
        """
        
        try:
            result = self.db_client.fetch_one(sql, (cve_id, snapshot_hash))
            return result['exists'] if result else False
        except Exception as e:
            logger.error(f"Failed to check snapshot existence: {e}")
            return False
    
    def get_context_stats(self) -> Dict[str, Any]:
        """
        Get context snapshot statistics.
        
        Returns:
            Dictionary with context statistics
        """
        sql = """
        SELECT 
            COUNT(*) as total_snapshots,
            COUNT(DISTINCT cve_id) as unique_cves,
            COUNT(DISTINCT source) as unique_sources,
            MIN(created_at) as first_snapshot,
            MAX(created_at) as last_snapshot
        FROM cve_context_snapshot
        """
        
        try:
            result = self.db_client.fetch_one(sql)
            return dict(result) if result else {}
        except Exception as e:
            logger.error(f"Failed to get context stats: {e}")
            return {}
    
    def get_sources_by_cve(self, cve_id: str) -> List[str]:
        """
        Get unique sources for a CVE's context snapshots.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            List of unique sources
        """
        sql = """
        SELECT DISTINCT source
        FROM cve_context_snapshot
        WHERE cve_id = %s
        ORDER BY source
        """
        
        try:
            results = self.db_client.fetch_all(sql, (cve_id,))
            return [row['source'] for row in results]
        except Exception as e:
            logger.error(f"Failed to get sources for CVE {cve_id}: {e}")
            return []
    
    def delete_old_snapshots(self, days: int = 30) -> int:
        """
        Delete old context snapshots.
        
        Args:
            days: Delete snapshots older than this many days
            
        Returns:
            Number of snapshots deleted
        """
        sql = """
        DELETE FROM cve_context_snapshot
        WHERE created_at < NOW() - INTERVAL '%s days'
        """
        
        try:
            self.db_client.execute(sql, (days,))
            # Note: Need to get affected rows count
            logger.info(f"Deleted context snapshots older than {days} days")
            return 1
        except Exception as e:
            logger.error(f"Failed to delete old context snapshots: {e}")
            return 0
    
    def get_snapshot_by_hash(self, snapshot_hash: str) -> Optional[Dict[str, Any]]:
        """
        Get context snapshot by hash.
        
        Args:
            snapshot_hash: Snapshot hash
            
        Returns:
            Context snapshot or None
        """
        sql = """
        SELECT 
            id, cve_id, source, snapshot_json, created_at
        FROM cve_context_snapshot
        WHERE snapshot_hash = %s
        """
        
        try:
            result = self.db_client.fetch_one(sql, (snapshot_hash,))
            if result:
                # Parse JSON if needed
                if isinstance(result['snapshot_json'], str):
                    result['snapshot_json'] = json.loads(result['snapshot_json'])
                return result
        except Exception as e:
            logger.error(f"Failed to get context snapshot by hash {snapshot_hash}: {e}")
        
        return None
    
    def compare_snapshots(self, snapshot_id_1: int, snapshot_id_2: int) -> Dict[str, Any]:
        """
        Compare two context snapshots.
        
        Args:
            snapshot_id_1: First snapshot ID
            snapshot_id_2: Second snapshot ID
            
        Returns:
            Comparison results
        """
        snapshot1 = self.get_context_snapshot(snapshot_id_1)
        snapshot2 = self.get_context_snapshot(snapshot_id_2)
        
        if not snapshot1 or not snapshot2:
            return {"error": "One or both snapshots not found"}
        
        result = {
            "snapshot1_id": snapshot_id_1,
            "snapshot2_id": snapshot_id_2,
            "same_cve": snapshot1['cve_id'] == snapshot2['cve_id'],
            "same_source": snapshot1['source'] == snapshot2['source'],
            "same_hash": snapshot1['snapshot_hash'] == snapshot2['snapshot_hash'],
            "age_difference_days": None
        }
        
        # Calculate age difference
        if snapshot1['created_at'] and snapshot2['created_at']:
            # This would require date parsing - simplified for now
            result["snapshot1_created"] = snapshot1['created_at']
            result["snapshot2_created"] = snapshot2['created_at']
        
        return result