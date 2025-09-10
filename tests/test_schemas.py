"""Tests for schemas module."""

import pytest
from datetime import datetime
from pathlib import Path

from redteam_automation.schemas import (
    SeverityLevel, FindingStatus, ToolType, ScopeTarget, Scope,
    Finding, ScanResult, BurpIssue, KnowledgeEntry, EngagementReport,
    StepLog, EngagementConfig
)


class TestSeverityLevel:
    """Test SeverityLevel enum."""
    
    def test_severity_levels(self):
        """Test all severity levels exist."""
        assert SeverityLevel.CRITICAL == "critical"
        assert SeverityLevel.HIGH == "high"
        assert SeverityLevel.MEDIUM == "medium"
        assert SeverityLevel.LOW == "low"
        assert SeverityLevel.INFO == "info"


class TestFindingStatus:
    """Test FindingStatus enum."""
    
    def test_finding_statuses(self):
        """Test all finding statuses exist."""
        assert FindingStatus.NEW == "new"
        assert FindingStatus.REVIEWING == "reviewing"
        assert FindingStatus.TRUE_POSITIVE == "true_positive"
        assert FindingStatus.FALSE_POSITIVE == "false_positive"
        assert FindingStatus.DUPLICATE == "duplicate"


class TestToolType:
    """Test ToolType enum."""
    
    def test_tool_types(self):
        """Test all tool types exist."""
        assert ToolType.SUBFINDER == "subfinder"
        assert ToolType.HTTPX == "httpx"
        assert ToolType.NUCLEI == "nuclei"
        assert ToolType.BURP == "burp"
        assert ToolType.MANUAL == "manual"


class TestScopeTarget:
    """Test ScopeTarget model."""
    
    def test_valid_scope_target(self):
        """Test creating valid scope target."""
        target = ScopeTarget(
            type="domain",
            value="example.com",
            description="Main domain"
        )
        assert target.type == "domain"
        assert target.value == "example.com"
        assert target.description == "Main domain"
    
    def test_scope_target_without_description(self):
        """Test scope target without description."""
        target = ScopeTarget(
            type="ip",
            value="192.168.1.1"
        )
        assert target.type == "ip"
        assert target.value == "192.168.1.1"
        assert target.description is None


class TestScope:
    """Test Scope model."""
    
    def test_valid_scope(self):
        """Test creating valid scope."""
        scope = Scope(
            included=[
                ScopeTarget(type="domain", value="example.com"),
                ScopeTarget(type="ip", value="192.168.1.0/24")
            ],
            excluded=[
                ScopeTarget(type="domain", value="admin.example.com")
            ]
        )
        assert len(scope.included) == 2
        assert len(scope.excluded) == 1
        assert scope.included[0].value == "example.com"
        assert scope.excluded[0].value == "admin.example.com"
    
    def test_empty_scope(self):
        """Test creating empty scope."""
        scope = Scope(included=[], excluded=[])
        assert len(scope.included) == 0
        assert len(scope.excluded) == 0


class TestFinding:
    """Test Finding model."""
    
    def test_valid_finding(self):
        """Test creating valid finding."""
        finding = Finding(
            id="finding-1",
            title="SQL Injection",
            description="SQL injection vulnerability found",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            target="https://example.com/login",
            tool="nuclei",
            status=FindingStatus.NEW,
            references=["https://owasp.org/www-community/attacks/SQL_Injection"]
        )
        assert finding.id == "finding-1"
        assert finding.title == "SQL Injection"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == 0.9
        assert finding.status == FindingStatus.NEW
        assert len(finding.references) == 1
    
    def test_finding_with_ai_analysis(self):
        """Test finding with AI analysis."""
        finding = Finding(
            id="finding-2",
            title="XSS Vulnerability",
            description="Cross-site scripting found",
            severity=SeverityLevel.MEDIUM,
            confidence=0.8,
            target="https://example.com/search",
            tool="burp",
            ai_analysis="This appears to be a reflected XSS vulnerability"
        )
        assert finding.ai_analysis == "This appears to be a reflected XSS vulnerability"
    
    def test_finding_confidence_validation(self):
        """Test finding confidence validation."""
        # Valid confidence
        finding = Finding(
            id="finding-3",
            title="Test Finding",
            description="Test description",
            severity=SeverityLevel.LOW,
            confidence=0.5,
            target="example.com",
            tool="manual"
        )
        assert finding.confidence == 0.5
        
        # Test boundary values
        finding_min = Finding(
            id="finding-4",
            title="Test Finding",
            description="Test description",
            severity=SeverityLevel.LOW,
            confidence=0.0,
            target="example.com",
            tool="manual"
        )
        assert finding_min.confidence == 0.0
        
        finding_max = Finding(
            id="finding-5",
            title="Test Finding",
            description="Test description",
            severity=SeverityLevel.LOW,
            confidence=1.0,
            target="example.com",
            tool="manual"
        )
        assert finding_max.confidence == 1.0


class TestScanResult:
    """Test ScanResult model."""
    
    def test_valid_scan_result(self):
        """Test creating valid scan result."""
        scan_result = ScanResult(
            tool="nuclei",
            target="example.com",
            status="completed",
            findings_count=5,
            timestamp=datetime.now()
        )
        assert scan_result.tool == "nuclei"
        assert scan_result.target == "example.com"
        assert scan_result.status == "completed"
        assert scan_result.findings_count == 5
        assert scan_result.error is None
    
    def test_scan_result_with_error(self):
        """Test scan result with error."""
        scan_result = ScanResult(
            tool="httpx",
            target="invalid-domain",
            status="failed",
            findings_count=0,
            error="DNS resolution failed"
        )
        assert scan_result.status == "failed"
        assert scan_result.error == "DNS resolution failed"
        assert scan_result.findings_count == 0


class TestBurpIssue:
    """Test BurpIssue model."""
    
    def test_valid_burp_issue(self):
        """Test creating valid Burp issue."""
        issue = BurpIssue(
            type="SQL injection",
            name="SQL injection vulnerability",
            host="example.com",
            path="/login",
            severity="High",
            confidence="Certain",
            description="SQL injection found in login form"
        )
        assert issue.type == "SQL injection"
        assert issue.name == "SQL injection vulnerability"
        assert issue.host == "example.com"
        assert issue.path == "/login"
        assert issue.severity == "High"
        assert issue.confidence == "Certain"


class TestKnowledgeEntry:
    """Test KnowledgeEntry model."""
    
    def test_valid_knowledge_entry(self):
        """Test creating valid knowledge entry."""
        entry = KnowledgeEntry(
            id="kb-1",
            title="SQL Injection Techniques",
            content="Various SQL injection techniques and mitigations",
            source="OWASP",
            tags=["sql", "injection", "web"],
            timestamp=datetime.now()
        )
        assert entry.id == "kb-1"
        assert entry.title == "SQL Injection Techniques"
        assert entry.source == "OWASP"
        assert len(entry.tags) == 3
        assert "sql" in entry.tags


class TestEngagementReport:
    """Test EngagementReport model."""
    
    def test_valid_engagement_report(self):
        """Test creating valid engagement report."""
        findings = [
            Finding(
                id="finding-1",
                title="Test Finding",
                description="Test description",
                severity=SeverityLevel.HIGH,
                confidence=0.9,
                target="example.com",
                tool="nuclei"
            )
        ]
        
        scan_results = [
            ScanResult(
                tool="nuclei",
                target="example.com",
                status="completed",
                findings_count=1
            )
        ]
        
        report = EngagementReport(
            id="engagement-1",
            target_scope="example.com",
            findings=findings,
            scan_results=scan_results,
            created_at=datetime.now()
        )
        
        assert report.id == "engagement-1"
        assert report.target_scope == "example.com"
        assert len(report.findings) == 1
        assert len(report.scan_results) == 1
        assert report.completed_at is None
        assert report.summary is None
    
    def test_completed_engagement_report(self):
        """Test completed engagement report."""
        report = EngagementReport(
            id="engagement-2",
            target_scope="example.com",
            findings=[],
            scan_results=[],
            created_at=datetime.now(),
            completed_at=datetime.now(),
            summary="Engagement completed successfully",
            recommendations=["Update software", "Implement WAF"]
        )
        
        assert report.completed_at is not None
        assert report.summary == "Engagement completed successfully"
        assert len(report.recommendations) == 2


class TestStepLog:
    """Test StepLog model."""
    
    def test_valid_step_log(self):
        """Test creating valid step log."""
        step = StepLog(
            timestamp=datetime.now(),
            phase="reconnaissance",
            action="Running subfinder",
            status="completed",
            duration=30.5,
            details={"targets_found": 15}
        )
        
        assert step.phase == "reconnaissance"
        assert step.action == "Running subfinder"
        assert step.status == "completed"
        assert step.duration == 30.5
        assert step.details["targets_found"] == 15


class TestEngagementConfig:
    """Test EngagementConfig model."""
    
    def test_valid_engagement_config(self):
        """Test creating valid engagement config."""
        config = EngagementConfig(
            target_scope="example.com",
            tools_enabled=["subfinder", "httpx", "nuclei"],
            max_threads=10,
            rate_limit=5,
            output_formats=["json", "html"]
        )
        
        assert config.target_scope == "example.com"
        assert len(config.tools_enabled) == 3
        assert config.max_threads == 10
        assert config.rate_limit == 5
        assert "json" in config.output_formats
    
    def test_engagement_config_defaults(self):
        """Test engagement config with defaults."""
        config = EngagementConfig(
            target_scope="example.com"
        )
        
        assert config.target_scope == "example.com"
        assert config.tools_enabled == ["subfinder", "httpx", "nuclei"]
        assert config.max_threads == 5
        assert config.rate_limit == 10
        assert config.output_formats == ["json", "html"]
        assert config.scope_file is None
        assert config.burp_file is None