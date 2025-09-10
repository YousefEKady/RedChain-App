"""Database models and enums for the red team automation framework."""

from enum import Enum

class EngagementStatus(Enum):
    """Engagement status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"