"""Pydantic schemas for red team automation framework."""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Any
from pathlib import Path

from pydantic import BaseModel, Field, validator, HttpUrl


class SeverityLevel(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Status of a finding."""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


class ToolType(str, Enum):
    """Types of tools used in scanning."""
    SUBFINDER = "subfinder"
    HTTPX = "httpx"
    NUCLEI = "nuclei"
    BURP_SUITE = "burp_suite"
    MANUAL = "manual"


class ScopeTarget(BaseModel):
    """Individual target in scope."""
    target: str = Field(..., description="Domain, IP, or URL")
    type: str = Field(..., description="Type: domain, ip, url")
    notes: Optional[str] = Field(None, description="Additional notes")

    @validator('target')
    def validate_target(cls, v):
        if not v or not v.strip():
            raise ValueError("Target cannot be empty")
        return v.strip()


class Scope(BaseModel):
    """Scope definition for red team engagement."""
    name: str = Field(..., description="Engagement name")
    description: Optional[str] = Field(None, description="Engagement description")
    targets: List[ScopeTarget] = Field(..., description="List of targets")
    excluded_targets: List[str] = Field(default_factory=list, description="Excluded targets")
    start_date: Optional[datetime] = Field(None, description="Engagement start date")
    end_date: Optional[datetime] = Field(None, description="Engagement end date")
    authorized_by: Optional[str] = Field(None, description="Authorization contact")
    
    @validator('targets')
    def validate_targets(cls, v):
        if not v:
            raise ValueError("At least one target must be specified")
        return v


class Finding(BaseModel):
    """Security finding from scans or manual testing."""
    id: str = Field(..., description="Unique finding ID")
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Detailed description")
    severity: SeverityLevel = Field(..., description="Severity level")
    status: FindingStatus = Field(default=FindingStatus.NEEDS_REVIEW, description="Finding status")
    target: str = Field(..., description="Affected target")
    url: Optional[str] = Field(None, description="Specific URL if applicable")
    tool: ToolType = Field(..., description="Tool that discovered the finding")
    raw_output: Optional[str] = Field(None, description="Raw tool output")
    cvss_score: Optional[float] = Field(None, description="CVSS score if available")
    cve_id: Optional[str] = Field(None, description="CVE ID if applicable")
    remediation: Optional[str] = Field(None, description="Remediation advice")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    discovered_at: datetime = Field(default_factory=datetime.now, description="Discovery timestamp")
    triage_notes: Optional[str] = Field(None, description="Triage analysis notes")
    confidence: Optional[float] = Field(None, description="Confidence score (0-1)")
    ai_analysis: Optional[str] = Field(None, description="AI-generated analysis and reasoning")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata from AI analysis")
    
    @validator('id')
    def validate_id(cls, v):
        if not v or not v.strip():
            raise ValueError("Finding ID cannot be empty")
        return v.strip()
    
    @validator('title')
    def validate_title(cls, v):
        if not v or not v.strip():
            raise ValueError("Finding title cannot be empty")
        if len(v.strip()) > 200:
            raise ValueError("Finding title cannot exceed 200 characters")
        return v.strip()
    
    @validator('description')
    def validate_description(cls, v):
        if not v or not v.strip():
            raise ValueError("Finding description cannot be empty")
        return v.strip()
    
    @validator('target')
    def validate_target(cls, v):
        if not v or not v.strip():
            raise ValueError("Target cannot be empty")
        return v.strip()
    
    @validator('cvss_score')
    def validate_cvss_score(cls, v):
        if v is not None and (v < 0.0 or v > 10.0):
            raise ValueError("CVSS score must be between 0.0 and 10.0")
        return v
    
    @validator('confidence')
    def validate_confidence(cls, v):
        if v is not None and (v < 0.0 or v > 1.0):
            raise ValueError("Confidence score must be between 0.0 and 1.0")
        return v
    
    @validator('cve_id')
    def validate_cve_id(cls, v):
        if v is not None and v.strip():
            import re
            if not re.match(r'^CVE-\d{4}-\d{4,}$', v.strip()):
                raise ValueError("CVE ID must follow format CVE-YYYY-NNNN")
            return v.strip()
        return v


class ScanResult(BaseModel):
    """Result from a tool scan."""
    tool: ToolType = Field(..., description="Tool used")
    target: str = Field(..., description="Target scanned")
    command: str = Field(..., description="Command executed")
    exit_code: int = Field(..., description="Exit code")
    stdout: str = Field(default="", description="Standard output")
    stderr: str = Field(default="", description="Standard error")
    duration: float = Field(..., description="Execution duration in seconds")
    timestamp: datetime = Field(default_factory=datetime.now, description="Execution timestamp")
    findings: List[Finding] = Field(default_factory=list, description="Extracted findings")
    
    @validator('target')
    def validate_target(cls, v):
        if not v or not v.strip():
            raise ValueError("Target cannot be empty")
        return v.strip()
    
    @validator('command')
    def validate_command(cls, v):
        if not v or not v.strip():
            raise ValueError("Command cannot be empty")
        return v.strip()
    
    @validator('duration')
    def validate_duration(cls, v):
        if v < 0:
            raise ValueError("Duration cannot be negative")
        return v
    
    @validator('exit_code')
    def validate_exit_code(cls, v):
        if v < 0 or v > 255:
            raise ValueError("Exit code must be between 0 and 255")
        return v


class BurpIssue(BaseModel):
    """Burp Suite issue from XML/JSON export."""
    serial_number: Optional[str] = Field(None, description="Issue serial number")
    type: str = Field(..., description="Issue type")
    name: str = Field(..., description="Issue name")
    host: str = Field(..., description="Target host")
    path: str = Field(..., description="URL path")
    location: Optional[str] = Field(None, description="Issue location")
    severity: str = Field(..., description="Severity level")
    confidence: str = Field(..., description="Confidence level")
    issue_background: Optional[str] = Field(None, description="Issue background")
    remediation_background: Optional[str] = Field(None, description="Remediation background")
    issue_detail: Optional[str] = Field(None, description="Detailed issue description")
    remediation_detail: Optional[str] = Field(None, description="Detailed remediation")
    vulnerability_classifications: List[str] = Field(default_factory=list, description="Classifications")
    
    @validator('type')
    def validate_type(cls, v):
        if not v or not v.strip():
            raise ValueError("Issue type cannot be empty")
        return v.strip()
    
    @validator('name')
    def validate_name(cls, v):
        if not v or not v.strip():
            raise ValueError("Issue name cannot be empty")
        return v.strip()
    
    @validator('host')
    def validate_host(cls, v):
        if not v or not v.strip():
            raise ValueError("Host cannot be empty")
        return v.strip()
    
    @validator('path')
    def validate_path(cls, v):
        if not v or not v.strip():
            raise ValueError("Path cannot be empty")
        return v.strip()
    
    @validator('severity')
    def validate_severity(cls, v):
        if not v or not v.strip():
            raise ValueError("Severity cannot be empty")
        valid_severities = ['high', 'medium', 'low', 'information']
        if v.strip().lower() not in valid_severities:
            raise ValueError(f"Severity must be one of: {', '.join(valid_severities)}")
        return v.strip().lower()
    
    @validator('confidence')
    def validate_confidence(cls, v):
        if not v or not v.strip():
            raise ValueError("Confidence cannot be empty")
        valid_confidences = ['certain', 'firm', 'tentative']
        if v.strip().lower() not in valid_confidences:
            raise ValueError(f"Confidence must be one of: {', '.join(valid_confidences)}")
        return v.strip().lower()


class KnowledgeEntry(BaseModel):
    """Knowledge base entry for techniques and methodologies."""
    id: str = Field(..., description="Unique entry ID")
    title: str = Field(..., description="Entry title")
    content: str = Field(..., description="Entry content")
    category: str = Field(..., description="Category (technique, payload, methodology)")
    tags: List[str] = Field(default_factory=list, description="Tags for categorization")
    source: Optional[str] = Field(None, description="Source of the knowledge")
    created_at: datetime = Field(default_factory=datetime.now, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.now, description="Last update timestamp")
    effectiveness_score: Optional[float] = Field(None, description="Effectiveness score (0-1)")


class EngagementReport(BaseModel):
    """Final engagement report."""
    engagement_id: str = Field(..., description="Unique engagement ID")
    scope: Scope = Field(..., description="Engagement scope")
    executive_summary: str = Field(..., description="Executive summary")
    methodology: str = Field(..., description="Testing methodology")
    findings: List[Finding] = Field(..., description="All findings")
    statistics: Dict[str, Any] = Field(default_factory=dict, description="Engagement statistics")
    recommendations: List[str] = Field(default_factory=list, description="General recommendations")
    timeline: List[Dict[str, Any]] = Field(default_factory=list, description="Engagement timeline")
    tools_used: List[str] = Field(default_factory=list, description="Tools used in engagement")
    ai_insights: Optional[Dict[str, Any]] = Field(default=None, description="AI-generated security insights")
    generated_at: datetime = Field(default_factory=datetime.now, description="Report generation timestamp")
    generated_by: str = Field(default="Red Team Automation Framework", description="Report generator")


class StepLog(BaseModel):
    """Individual step in the engagement process."""
    timestamp: datetime = Field(default_factory=datetime.now, description="Step timestamp")
    phase: str = Field(..., description="Engagement phase")
    action: str = Field(..., description="Action performed")
    details: Optional[str] = Field(None, description="Additional details")
    status: str = Field(..., description="Step status (started, completed, failed)")
    duration: Optional[float] = Field(None, description="Duration in seconds")


class EngagementConfig(BaseModel):
    """Configuration for an engagement run."""
    engagement_id: str = Field(..., description="Unique engagement identifier")
    output_dir: Path = Field(..., description="Output directory")
    enable_subfinder: bool = Field(default=True, description="Enable subdomain enumeration")
    enable_httpx: bool = Field(default=True, description="Enable HTTP probing")
    enable_nuclei: bool = Field(default=True, description="Enable vulnerability scanning")
    nuclei_templates: Optional[List[str]] = Field(None, description="Specific Nuclei templates")
    rate_limit: int = Field(default=60, description="Requests per minute")
    timeout: int = Field(default=300, description="Tool timeout in seconds")
    dry_run: bool = Field(default=False, description="Dry run mode")
    burp_logs: List[Path] = Field(default_factory=list, description="Burp Suite log files")
    
    @validator('engagement_id')
    def validate_engagement_id(cls, v):
        if not v or not v.strip():
            raise ValueError("Engagement ID cannot be empty")
        # Ensure safe filename characters
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v.strip()):
            raise ValueError("Engagement ID can only contain letters, numbers, underscores, and hyphens")
        return v.strip()
    
    @validator('rate_limit')
    def validate_rate_limit(cls, v):
        if v <= 0 or v > 10000:
            raise ValueError("Rate limit must be between 1 and 10000 requests per minute")
        return v
    
    @validator('timeout')
    def validate_timeout(cls, v):
        if v <= 0 or v > 3600:
            raise ValueError("Timeout must be between 1 and 3600 seconds")
        return v