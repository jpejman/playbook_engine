#!/usr/bin/env python3
"""
Timezone-aware timestamp utilities for continuous execution system.
"""

from datetime import datetime, timezone
from typing import Dict, Any


def get_utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


def get_utc_now_iso() -> str:
    """Get current UTC time as ISO format string."""
    return get_utc_now().isoformat()


def datetime_to_iso(dt: datetime) -> str:
    """Convert datetime to ISO format string."""
    if dt.tzinfo is None:
        # Assume UTC if no timezone info
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def calculate_duration_seconds(start: datetime, end: datetime) -> float:
    """Calculate duration in seconds between two datetimes."""
    # Ensure both are timezone-aware
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    
    return (end - start).total_seconds()