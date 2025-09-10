"""Migration to add automatic report generation tracking fields."""

import sqlite3
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def migrate_database(db_path: str):
    """Add fields for tracking automatic report generation."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(engagements)")
        columns = [column[1] for column in cursor.fetchall()]
        
        migrations_applied = []
        
        # Add auto_report_generated column
        if 'auto_report_generated' not in columns:
            cursor.execute(
                "ALTER TABLE engagements ADD COLUMN auto_report_generated INTEGER DEFAULT 0"
            )
            migrations_applied.append('auto_report_generated')
            
        # Add batch_report_generated column
        if 'batch_report_generated' not in columns:
            cursor.execute(
                "ALTER TABLE engagements ADD COLUMN batch_report_generated INTEGER DEFAULT 0"
            )
            migrations_applied.append('batch_report_generated')
            
        # Add last_report_generated timestamp
        if 'last_report_generated' not in columns:
            cursor.execute(
                "ALTER TABLE engagements ADD COLUMN last_report_generated TEXT"
            )
            migrations_applied.append('last_report_generated')
            
        # Add report_generation_count
        if 'report_generation_count' not in columns:
            cursor.execute(
                "ALTER TABLE engagements ADD COLUMN report_generation_count INTEGER DEFAULT 0"
            )
            migrations_applied.append('report_generation_count')
            
        # Create report_generation_log table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report_generation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                format_type TEXT NOT NULL,
                trigger_type TEXT NOT NULL,
                status TEXT NOT NULL,
                report_path TEXT,
                error_message TEXT,
                file_size INTEGER,
                generation_time_seconds REAL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (engagement_id) REFERENCES engagements (id)
            )
        """)
        migrations_applied.append('report_generation_log table')
        
        # Create index for faster queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_report_log_engagement 
            ON report_generation_log(engagement_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_report_log_created 
            ON report_generation_log(created_at)
        """)
        
        conn.commit()
        conn.close()
        
        if migrations_applied:
            logger.info(f"Applied database migrations: {', '.join(migrations_applied)}")
        else:
            logger.info("No database migrations needed")
            
        return True
        
    except Exception as e:
        logger.error(f"Database migration failed: {e}")
        return False

def rollback_migration(db_path: str):
    """Rollback the migration (remove added columns)."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
        # This is a simplified rollback - in production, you'd want more sophisticated handling
        
        logger.warning("Rollback not implemented - SQLite doesn't support DROP COLUMN")
        logger.warning("Manual intervention required to remove columns")
        
        conn.close()
        return False
        
    except Exception as e:
        logger.error(f"Migration rollback failed: {e}")
        return False

if __name__ == "__main__":
    # Run migration if called directly
    from config import settings
    db_path = Path(settings.output_dir) / "engagements.db"
    migrate_database(str(db_path))