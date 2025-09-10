"""Database connection and session management."""

import sqlite3
from contextlib import contextmanager
from typing import Generator
from config import settings


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Get database connection context manager.
    
    Yields:
        sqlite3.Connection: Database connection
    """
    conn = None
    try:
        conn = sqlite3.connect(settings.SQLITE_DB_PATH)
        conn.row_factory = sqlite3.Row  # Enable dict-like access to rows
        yield conn
    except Exception as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn:
            conn.close()


def init_database():
    """Initialize the database with required tables."""
    with get_db() as conn:
        # Create engagements table if it doesn't exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS engagements (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target_url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                auto_report_enabled BOOLEAN DEFAULT 0,
                report_format TEXT DEFAULT 'html',
                report_schedule TEXT,
                webhook_url TEXT
            )
        """)
        
        # Create reports table if it doesn't exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                report_path TEXT NOT NULL,
                format TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (engagement_id) REFERENCES engagements (id)
            )
        """)
        
        conn.commit()