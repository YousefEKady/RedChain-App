"""Logging utilities for red team automation framework."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

import structlog
from structlog.stdlib import LoggerFactory

from config import settings
from schemas import StepLog


class StepsLogger:
    """Logger for engagement steps with append-only steps.txt file."""
    
    def __init__(self, steps_file: Optional[str] = None):
        self.steps_file = Path(steps_file or settings.steps_log_file)
        self.steps_file.parent.mkdir(parents=True, exist_ok=True)
        
    def log_step(self, phase: str, action: str, status: str = "started", 
                 details: Optional[str] = None, duration: Optional[float] = None) -> None:
        """Log a step to the steps.txt file.
        
        Args:
            phase: The engagement phase (e.g., 'reconnaissance', 'scanning')
            action: The specific action being performed
            status: Status of the step ('started', 'completed', 'failed')
            details: Additional details about the step
            duration: Duration in seconds (for completed steps)
        """
        # Input validation
        if not phase or not isinstance(phase, str):
            raise ValueError("Phase must be a non-empty string")
        if not action or not isinstance(action, str):
            raise ValueError("Action must be a non-empty string")
        if status not in ['started', 'completed', 'failed', 'stopped']:
            raise ValueError("Status must be one of: started, completed, failed, stopped")
        if duration is not None and (not isinstance(duration, (int, float)) or duration < 0):
            raise ValueError("Duration must be a non-negative number")
        step = StepLog(
            phase=phase,
            action=action,
            status=status,
            details=details,
            duration=duration
        )
        
        # Format step for logging
        timestamp_str = step.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp_str}] {phase.upper()}: {action} - {status.upper()}"
        
        if details:
            log_line += f" | {details}"
        if duration is not None:
            log_line += f" | Duration: {duration:.2f}s"
            
        # Append to steps.txt file with error handling
        try:
            with open(self.steps_file, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
        except (IOError, OSError) as e:
            # Fallback to stderr if file logging fails
            import sys
            print(f"ERROR: Failed to write to steps log: {e}", file=sys.stderr)
            print(f"STEP: {log_line}", file=sys.stderr)
            
    def log_phase_start(self, phase: str, details: Optional[str] = None) -> None:
        """Log the start of an engagement phase."""
        self.log_step(phase, "Phase started", "started", details)
        
    def log_phase_complete(self, phase: str, duration: Optional[float] = None, 
                          details: Optional[str] = None) -> None:
        """Log the completion of an engagement phase."""
        self.log_step(phase, "Phase completed", "completed", details, duration)
        
    def log_tool_execution(self, tool: str, target: str, command: str, 
                          status: str = "started") -> None:
        """Log tool execution."""
        action = f"Executing {tool} on {target}"
        details = f"Command: {command}"
        self.log_step("scanning", action, status, details)
        
    def log_finding_discovered(self, finding_title: str, severity: str, 
                              target: str, tool: str) -> None:
        """Log discovery of a new finding."""
        action = f"Finding discovered: {finding_title}"
        details = f"Severity: {severity} | Target: {target} | Tool: {tool}"
        self.log_step("analysis", action, "completed", details)
        
    def log_triage_result(self, finding_id: str, result: str, confidence: float) -> None:
        """Log triage analysis result."""
        action = f"Triage completed for finding {finding_id}"
        details = f"Result: {result} | Confidence: {confidence:.2f}"
        self.log_step("triage", action, "completed", details)
        
    def clear_log(self) -> None:
        """Clear the steps log file (use with caution)."""
        if self.steps_file.exists():
            self.steps_file.unlink()


def setup_logging() -> None:
    """Setup structured logging configuration."""
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, settings.log_level.upper()),
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("redteam_automation.log")
        ]
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Configured structlog logger
    """
    return structlog.get_logger(name)


# Global steps logger instance
steps_logger = StepsLogger()