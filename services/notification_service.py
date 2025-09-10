"""Notification service for report generation events."""

import asyncio
import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any
import aiohttp
from pathlib import Path

from config import settings

logger = logging.getLogger(__name__)

class NotificationService:
    """Service for sending notifications about report generation."""
    
    def __init__(self):
        self.webhook_url = settings.report_notification_webhook
        self.discord_webhook_url = settings.discord_webhook_url
        
    async def send_report_notification(
        self, 
        engagement_id: str, 
        format_type: str, 
        report_path: str, 
        trigger_type: str
    ):
        """Send notification when a report is generated."""
        if not self.webhook_url:
            logger.debug("No webhook URL configured, skipping notification")
            return
            
        try:
            payload = {
                "event": "report_generated",
                "timestamp": datetime.now().isoformat(),
                "data": {
                    "engagement_id": engagement_id,
                    "format": format_type,
                    "report_path": str(report_path),
                    "trigger_type": trigger_type,
                    "file_size": self._get_file_size(report_path)
                }
            }
            
            await self._send_webhook(payload)
            logger.info(f"Sent report notification for {engagement_id} ({format_type})")
            
        except Exception as e:
            logger.error(f"Failed to send report notification: {e}")
            
    async def send_batch_completion_notification(
        self, 
        total_engagements: int, 
        successful: int, 
        failed: int
    ):
        """Send notification when batch report generation completes."""
        if not self.webhook_url:
            return
            
        try:
            payload = {
                "event": "batch_reports_completed",
                "timestamp": datetime.now().isoformat(),
                "data": {
                    "total_engagements": total_engagements,
                    "successful_reports": successful,
                    "failed_reports": failed,
                    "success_rate": (successful / total_engagements * 100) if total_engagements > 0 else 0
                }
            }
            
            await self._send_webhook(payload)
            logger.info(f"Sent batch completion notification: {successful}/{total_engagements} successful")
            
        except Exception as e:
            logger.error(f"Failed to send batch completion notification: {e}")
            
    async def send_error_notification(
        self, 
        engagement_id: str, 
        error_message: str, 
        context: Dict[str, Any] = None
    ):
        """Send notification when report generation fails."""
        if not self.webhook_url:
            return
            
        try:
            payload = {
                "event": "report_generation_failed",
                "timestamp": datetime.now().isoformat(),
                "data": {
                    "engagement_id": engagement_id,
                    "error_message": error_message,
                    "context": context or {}
                }
            }
            
            await self._send_webhook(payload)
            logger.info(f"Sent error notification for {engagement_id}")
            
        except Exception as e:
            logger.error(f"Failed to send error notification: {e}")
            
    async def send_scheduler_status_notification(self, status: Dict[str, Any]):
        """Send notification about scheduler status changes."""
        if not self.webhook_url:
            return
            
        try:
            payload = {
                "event": "scheduler_status_update",
                "timestamp": datetime.now().isoformat(),
                "data": status
            }
            
            await self._send_webhook(payload)
            logger.info("Sent scheduler status notification")
            
        except Exception as e:
            logger.error(f"Failed to send scheduler status notification: {e}")
    
    async def send_engagement_completion_notification(
        self,
        engagement_id: str,
        engagement_name: str,
        total_findings: int,
        critical_findings: int,
        high_findings: int,
        duration: str,
        report_path: Optional[str] = None
    ):
        """Send Discord notification when an engagement completes."""
        if not self.discord_webhook_url:
            logger.debug("No Discord webhook URL configured, skipping engagement notification")
            return
            
        try:
            # Create Discord embed format
            embed = {
                "title": "🎯 Red Team Engagement Completed",
                "description": f"**{engagement_name}** has finished execution",
                "color": 0x00ff00 if critical_findings == 0 else 0xff6b35 if critical_findings > 0 else 0xffa500,
                "fields": [
                    {
                        "name": "📊 Findings Summary",
                        "value": f"**Total:** {total_findings}\n**Critical:** {critical_findings}\n**High:** {high_findings}",
                        "inline": True
                    },
                    {
                        "name": "⏱️ Duration",
                        "value": duration,
                        "inline": True
                    },
                    {
                        "name": "🆔 Engagement ID",
                        "value": f"`{engagement_id}`",
                        "inline": True
                    }
                ],
                "timestamp": datetime.now().isoformat(),
                "footer": {
                    "text": "Red Team Automation Framework"
                }
            }
            
            if report_path:
                embed["fields"].append({
                    "name": "📄 Report",
                    "value": f"Generated at: `{report_path}`",
                    "inline": False
                })
            
            payload = {
                "embeds": [embed]
            }
            
            await self._send_discord_webhook(payload)
            logger.info(f"Sent Discord engagement completion notification for {engagement_id}")
            
        except Exception as e:
            logger.error(f"Failed to send Discord engagement completion notification: {e}")
            
    async def _send_webhook(self, payload: Dict[str, Any]):
        """Send webhook HTTP request."""
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "RedTeam-Automation-Scheduler/1.0"
                    }
                ) as response:
                    if response.status >= 400:
                        logger.warning(
                            f"Webhook returned status {response.status}: {await response.text()}"
                        )
                    else:
                        logger.debug(f"Webhook sent successfully (status: {response.status})")
                        
        except asyncio.TimeoutError:
            logger.error("Webhook request timed out")
        except Exception as e:
            logger.error(f"Error sending webhook: {e}")
    
    async def _send_discord_webhook(self, payload: Dict[str, Any]):
        """Send Discord webhook HTTP request."""
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    self.discord_webhook_url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "RedTeam-Automation/1.0"
                    }
                ) as response:
                    if response.status >= 400:
                        logger.warning(
                            f"Discord webhook returned status {response.status}: {await response.text()}"
                        )
                    else:
                        logger.debug(f"Discord webhook sent successfully (status: {response.status})")
                        
        except asyncio.TimeoutError:
            logger.error("Discord webhook request timed out")
        except Exception as e:
            logger.error(f"Error sending Discord webhook: {e}")
            
    def _get_file_size(self, file_path: str) -> Optional[int]:
        """Get file size in bytes."""
        try:
            return Path(file_path).stat().st_size
        except Exception:
            return None
            
    def test_webhook(self) -> bool:
        """Test webhook connectivity."""
        if not self.webhook_url:
            logger.warning("No webhook URL configured")
            return False
            
        try:
            # Run async test in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            async def _test():
                payload = {
                    "event": "webhook_test",
                    "timestamp": datetime.now().isoformat(),
                    "data": {
                        "message": "This is a test notification from RedTeam Automation"
                    }
                }
                await self._send_webhook(payload)
                return True
                
            result = loop.run_until_complete(_test())
            loop.close()
            return result
            
        except Exception as e:
            logger.error(f"Webhook test failed: {e}")
            return False