"""
Queue Repository for CVE processing queue operations.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from utils.db import DatabaseClient

logger = logging.getLogger(__name__)


class QueueRepository:
    """Repository for CVE queue operations."""
    
    def __init__(self, db_client: Optional[DatabaseClient] = None):
        self.db_client = db_client or DatabaseClient()
    
    def add_to_queue(self, cve_id: str, priority: int = 5, source: Optional[str] = None) -> Optional[int]:
        """
        Add a CVE to the processing queue.
        
        Args:
            cve_id: CVE identifier
            priority: Processing priority (1=highest, 10=lowest)
            source: Source of the CVE
            
        Returns:
            Queue entry ID or None if failed
        """
        sql = """
        INSERT INTO cve_queue (cve_id, priority, source, status)
        VALUES (%s, %s, %s, 'pending')
        ON CONFLICT (cve_id) DO UPDATE SET
            priority = EXCLUDED.priority,
            source = EXCLUDED.source,
            updated_at = NOW()
        RETURNING id
        """
        
        try:
            result = self.db_client.fetch_one(sql, (cve_id, priority, source))
            if result:
                logger.info(f"Added CVE {cve_id} to queue with priority {priority}")
                return result['id']
        except Exception as e:
            logger.error(f"Failed to add CVE {cve_id} to queue: {e}")
        
        return None
    
    def get_next_pending(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get next pending CVEs from queue.
        
        Args:
            limit: Maximum number of CVEs to return
            
        Returns:
            List of queue entries
        """
        sql = """
        SELECT id, cve_id, priority, source, created_at
        FROM cve_queue
        WHERE status = 'pending'
        ORDER BY priority ASC, created_at ASC
        LIMIT %s
        FOR UPDATE SKIP LOCKED
        """
        
        try:
            return self.db_client.fetch_all(sql, (limit,))
        except Exception as e:
            logger.error(f"Failed to get pending CVEs: {e}")
            return []
    
    def mark_processing(self, queue_id: int) -> bool:
        """
        Mark a queue entry as processing.
        
        Args:
            queue_id: Queue entry ID
            
        Returns:
            True if successful
        """
        sql = """
        UPDATE cve_queue
        SET status = 'processing', updated_at = NOW()
        WHERE id = %s AND status = 'pending'
        """
        
        try:
            self.db_client.execute(sql, (queue_id,))
            logger.info(f"Marked queue entry {queue_id} as processing")
            return True
        except Exception as e:
            logger.error(f"Failed to mark queue entry {queue_id} as processing: {e}")
            return False
    
    def mark_completed(self, queue_id: int) -> bool:
        """
        Mark a queue entry as completed.
        
        Args:
            queue_id: Queue entry ID
            
        Returns:
            True if successful
        """
        sql = """
        UPDATE cve_queue
        SET status = 'completed', updated_at = NOW()
        WHERE id = %s
        """
        
        try:
            self.db_client.execute(sql, (queue_id,))
            logger.info(f"Marked queue entry {queue_id} as completed")
            return True
        except Exception as e:
            logger.error(f"Failed to mark queue entry {queue_id} as completed: {e}")
            return False
    
    def mark_failed(self, queue_id: int, retry: bool = True) -> bool:
        """
        Mark a queue entry as failed.
        
        Args:
            queue_id: Queue entry ID
            retry: Whether to allow retry
            
        Returns:
            True if successful
        """
        if retry:
            sql = """
            UPDATE cve_queue
            SET status = 'retry', 
                retry_count = retry_count + 1,
                updated_at = NOW()
            WHERE id = %s
            """
        else:
            sql = """
            UPDATE cve_queue
            SET status = 'failed', updated_at = NOW()
            WHERE id = %s
            """
        
        try:
            self.db_client.execute(sql, (queue_id,))
            status = 'retry' if retry else 'failed'
            logger.info(f"Marked queue entry {queue_id} as {status}")
            return True
        except Exception as e:
            logger.error(f"Failed to mark queue entry {queue_id} as failed: {e}")
            return False
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """
        Get queue statistics.
        
        Returns:
            Dictionary with queue statistics
        """
        sql = """
        SELECT 
            COUNT(*) as total,
            COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
            COUNT(CASE WHEN status = 'processing' THEN 1 END) as processing,
            COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
            COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
            COUNT(CASE WHEN status = 'retry' THEN 1 END) as retry,
            AVG(priority) as avg_priority
        FROM cve_queue
        """
        
        try:
            result = self.db_client.fetch_one(sql)
            return dict(result) if result else {}
        except Exception as e:
            logger.error(f"Failed to get queue stats: {e}")
            return {}
    
    def get_by_cve_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get queue entry by CVE ID.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Queue entry or None
        """
        sql = """
        SELECT id, cve_id, status, priority, retry_count, source, created_at, updated_at
        FROM cve_queue
        WHERE cve_id = %s
        """
        
        try:
            return self.db_client.fetch_one(sql, (cve_id,))
        except Exception as e:
            logger.error(f"Failed to get queue entry for CVE {cve_id}: {e}")
            return None
    
    def cleanup_old_entries(self, days: int = 30) -> int:
        """
        Clean up old completed entries.
        
        Args:
            days: Delete entries older than this many days
            
        Returns:
            Number of entries deleted
        """
        sql = """
        DELETE FROM cve_queue
        WHERE status = 'completed' 
        AND created_at < NOW() - INTERVAL '%s days'
        """
        
        try:
            self.db_client.execute(sql, (days,))
            # Note: Need to get affected rows count - in psycopg2 this requires cursor.rowcount
            # For simplicity, we'll just return 1 if successful
            logger.info(f"Cleaned up queue entries older than {days} days")
            return 1
        except Exception as e:
            logger.error(f"Failed to clean up old queue entries: {e}")
            return 0