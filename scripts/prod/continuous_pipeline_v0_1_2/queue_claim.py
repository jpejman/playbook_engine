"""
Atomic queue claim logic
Version: v0.1.2
Timestamp (UTC): 2026-04-15
"""

from typing import Optional

import psycopg2.extras

from .db_clients import PlaybookEngineClient
from .models import ClaimedQueueItem


class QueueClaimService:
    def __init__(self):
        self.db = PlaybookEngineClient()

    def claim_one_pending(self) -> Optional[ClaimedQueueItem]:
        with self.db.get_connection() as conn:
            try:
                conn.autocommit = False

                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        """
                        WITH next_item AS (
                            SELECT id
                            FROM public.cve_queue
                            WHERE status = 'pending'
                            ORDER BY created_at ASC
                            FOR UPDATE SKIP LOCKED
                            LIMIT 1
                        )
                        UPDATE public.cve_queue q
                        SET status = 'processing',
                            updated_at = NOW()
                        FROM next_item
                        WHERE q.id = next_item.id
                        RETURNING q.id, q.cve_id, q.status, q.created_at, q.updated_at;
                        """
                    )
                    row = cur.fetchone()

                conn.commit()

                if not row:
                    return None

                return ClaimedQueueItem(
                    id=row["id"],
                    cve_id=row["cve_id"],
                    status=row["status"],
                    created_at=str(row["created_at"]) if row.get("created_at") else None,
                    updated_at=str(row["updated_at"]) if row.get("updated_at") else None,
                )

            except Exception:
                conn.rollback()
                raise