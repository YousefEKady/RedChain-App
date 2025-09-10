"""Background scheduler for automatic report generation."""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor
import threading
from croniter import croniter

from config import settings
from database.models import EngagementStatus
from database.database import get_db
from reporting.generator import ReportGenerator
# Removed to avoid circular import - will import locally where needed
from services.notification_service import NotificationService

logger = logging.getLogger(__name__)

class ReportScheduler:
    """Background scheduler for automatic report generation."""
    
    def __init__(self):
        self.running = False
        self.scheduler_thread = None
        self.executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_reports)
        self.notification_service = NotificationService()
        self.active_tasks = set()
        
    def start(self):
        """Start the background scheduler."""
        if self.running:
            logger.warning("Report scheduler is already running")
            return
            
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        logger.info("Report scheduler started")
        
    def stop(self):
        """Stop the background scheduler."""
        if not self.running:
            return
            
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        self.executor.shutdown(wait=True)
        logger.info("Report scheduler stopped")
        
    def _run_scheduler(self):
        """Main scheduler loop."""
        while self.running:
            try:
                # Check for completed engagements that need reports
                if settings.auto_report_on_completion:
                    self._check_completed_engagements()
                
                # Check scheduled report generation
                if settings.auto_report_schedule:
                    self._check_scheduled_reports()
                
                # Check batch report generation
                if settings.batch_report_generation:
                    self._check_batch_reports()
                    
            except Exception as e:
                logger.error(f"Error in report scheduler: {e}")
                
            # Sleep for 30 seconds before next check
            for _ in range(30):
                if not self.running:
                    break
                threading.Event().wait(1)
                
    def _check_completed_engagements(self):
        """Check for completed engagements that need automatic reports."""
        try:
            with get_db() as db:
                # Find completed engagements without reports
                completed_engagements = db.execute(
                        "SELECT * FROM engagements WHERE status = ? AND auto_report_enabled = 1",
                        (EngagementStatus.COMPLETED.value,)
                    ).fetchall()
                
                for engagement in completed_engagements:
                    if len(self.active_tasks) >= settings.max_concurrent_reports:
                        logger.info("Max concurrent reports reached, skipping")
                        break
                        
                    task_id = f"auto_{engagement['id']}"
                    if task_id not in self.active_tasks:
                        self._schedule_report_generation(engagement, "auto_completion")
                        
        except Exception as e:
            logger.error(f"Error checking completed engagements: {e}")
            
    def _check_scheduled_reports(self):
        """Check if it's time for scheduled report generation."""
        try:
            if not settings.auto_report_schedule:
                return
                
            # Parse cron expression
            cron = croniter(settings.auto_report_schedule, datetime.now())
            next_run = cron.get_next(datetime)
            
            # Check if we should run now (within 1 minute window)
            if abs((next_run - datetime.now()).total_seconds()) <= 60:
                with get_db() as db:
                    # Get all completed engagements for batch processing
                    engagements = db.execute(
                        "SELECT * FROM engagements WHERE status = ?",
                        (EngagementStatus.COMPLETED.value,)
                    ).fetchall()
                    
                    for engagement in engagements:
                        if len(self.active_tasks) >= settings.max_concurrent_reports:
                            break
                        self._schedule_report_generation(engagement, "scheduled")
                        
        except Exception as e:
            logger.error(f"Error in scheduled report check: {e}")
            
    def _check_batch_reports(self):
        """Check for batch report generation needs."""
        try:
            with get_db() as db:
                # Find engagements that might need batch processing
                old_engagements = db.execute(
                    """SELECT * FROM engagements 
                       WHERE status = ? AND 
                       datetime(created_at) < datetime('now', '-1 day') AND
                       batch_report_generated = 0""",
                    (EngagementStatus.COMPLETED.value,)
                ).fetchall()
                
                if len(old_engagements) >= 5:  # Batch when we have 5+ old engagements
                    self._schedule_batch_report_generation(old_engagements)
                    
        except Exception as e:
            logger.error(f"Error in batch report check: {e}")
            
    def _schedule_report_generation(self, engagement: Dict[str, Any], trigger_type: str):
        """Schedule report generation for a single engagement."""
        task_id = f"{trigger_type}_{engagement['id']}"
        
        if task_id in self.active_tasks:
            return
            
        self.active_tasks.add(task_id)
        future = self.executor.submit(
            asyncio.run, 
            self._generate_engagement_report(engagement, trigger_type, task_id)
        )
        future.add_done_callback(lambda f: self.active_tasks.discard(task_id))
        
    def _schedule_batch_report_generation(self, engagements: List[Dict[str, Any]]):
        """Schedule batch report generation."""
        task_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if task_id in self.active_tasks:
            return
            
        self.active_tasks.add(task_id)
        future = self.executor.submit(
            asyncio.run, 
            self._generate_batch_reports(engagements, task_id)
        )
        future.add_done_callback(lambda f: self.active_tasks.discard(task_id))
        
    async def _generate_engagement_report(self, engagement: Dict[str, Any], trigger_type: str, task_id: str):
        """Generate report for a single engagement."""
        from workflows.orchestrator import RedTeamOrchestrator
        
        try:
            logger.info(f"Starting {trigger_type} report generation for engagement {engagement['id']}")
            
            # Get report formats to generate
            formats = settings.auto_report_formats.split(',')
            
            for format_type in formats:
                format_type = format_type.strip()
                if not format_type:
                    continue
                    
                try:
                    # Generate report
                    generator = ReportGenerator()
                    
                    # Load engagement data
                    orchestrator = RedTeamOrchestrator()
                    report_data = orchestrator.get_engagement_report_data(engagement['id'])
                    
                    if format_type == 'html':
                        report_path = generator.generate_html_report(report_data)
                    elif format_type == 'markdown':
                        report_path = generator.generate_markdown_report(report_data)
                    elif format_type == 'json':
                        report_path = generator.generate_json_report(report_data)
                    else:
                        logger.warning(f"Unsupported format: {format_type}")
                        continue
                        
                    logger.info(f"Generated {format_type} report: {report_path}")
                    
                    # Send notification
                    await self.notification_service.send_report_notification(
                        engagement['id'],
                        format_type,
                        report_path,
                        trigger_type
                    )
                    
                except Exception as e:
                    logger.error(f"Error generating {format_type} report for {engagement['id']}: {e}")
                    
            # Mark as auto-generated
            with get_db() as db:
                db.execute(
                    "UPDATE engagements SET auto_report_generated = 1 WHERE id = ?",
                    (engagement['id'],)
                )
                db.commit()
                
        except Exception as e:
            logger.error(f"Error in report generation task {task_id}: {e}")
            
    async def _generate_batch_reports(self, engagements: List[Dict[str, Any]], task_id: str):
        """Generate reports for multiple engagements in batch."""
        try:
            logger.info(f"Starting batch report generation for {len(engagements)} engagements")
            
            successful = 0
            failed = 0
            
            for engagement in engagements:
                try:
                    await self._generate_engagement_report(engagement, "batch", f"{task_id}_{engagement['id']}")
                    successful += 1
                except Exception as e:
                    logger.error(f"Failed to generate report for engagement {engagement['id']}: {e}")
                    failed += 1
                    
            logger.info(f"Batch report generation completed: {successful} successful, {failed} failed")
            
            # Send batch completion notification
            await self.notification_service.send_batch_completion_notification(
                len(engagements), successful, failed
            )
            
        except Exception as e:
            logger.error(f"Error in batch report generation {task_id}: {e}")
            
    def get_status(self) -> Dict[str, Any]:
        """Get current scheduler status."""
        # Get completed reports count from database
        completed_count = 0
        try:
            with get_db() as db:
                result = db.execute(
                    "SELECT COUNT(*) as count FROM report_generation_log WHERE status = 'completed'"
                ).fetchone()
                completed_count = result['count'] if result else 0
        except Exception as e:
            logger.error(f"Error getting completed reports count: {e}")
            
        return {
            "running": self.running,
            "active_tasks": len(self.active_tasks),
            "max_concurrent": settings.max_concurrent_reports,
            "auto_generation_enabled": settings.auto_generate_reports,
            "auto_on_completion": settings.auto_report_on_completion,
            "batch_generation": settings.batch_report_generation,
            "schedule": settings.auto_report_schedule,
            "completed_reports": completed_count
        }

# Global scheduler instance
scheduler = ReportScheduler()