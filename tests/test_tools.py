"""Tests for tools modules."""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from redteam_automation.tools.project_discovery import ProjectDiscoveryTools, RateLimiter
from redteam_automation.tools.burp_parser import BurpSuiteParser
from redteam_automation.schemas import Scope, ScopeTarget, Finding, BurpIssue, SeverityLevel
from redteam_automation.utils.scope_validator import ScopeValidator
from redteam_automation.utils.logging import StepsLogger


class TestRateLimiter:
    """Test RateLimiter class."""
    
    def test_rate_limiter_creation(self):
        """Test rate limiter creation."""
        limiter = RateLimiter(requests_per_second=5)
        assert limiter.requests_per_second == 5
        assert limiter.min_interval == 0.2  # 1/5
    
    def test_rate_limiter_wait(self):
        """Test rate limiter wait functionality."""
        limiter = RateLimiter(requests_per_second=10)
        
        # First call should not wait
        start_time = datetime.now()
        limiter.wait()
        first_call_time = datetime.now()
        
        # Second call should wait
        limiter.wait()
        second_call_time = datetime.now()
        
        # Should have waited at least the minimum interval
        time_diff = (second_call_time - first_call_time).total_seconds()
        assert time_diff >= limiter.min_interval * 0.9  # Allow some tolerance


class TestProjectDiscoveryTools:
    """Test ProjectDiscoveryTools class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scope = Scope(
            included=[ScopeTarget(type="domain", value="example.com")],
            excluded=[]
        )
        self.scope_validator = ScopeValidator(self.scope)
        
        # Create temporary log file
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "steps.txt"
        self.steps_logger = StepsLogger(str(self.log_file))
        
        self.tools = ProjectDiscoveryTools(
            scope_validator=self.scope_validator,
            steps_logger=self.steps_logger
        )
    
    def teardown_method(self):
        """Clean up test fixtures."""
        if self.log_file.exists():
            self.log_file.unlink()
        Path(self.temp_dir).rmdir()
    
    @patch('subprocess.run')
    def test_run_subfinder_success(self, mock_run):
        """Test successful subfinder execution."""
        # Mock successful subprocess run
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "sub1.example.com\nsub2.example.com\n"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        results = self.tools.run_subfinder("example.com")
        
        assert len(results) == 2
        assert "sub1.example.com" in results
        assert "sub2.example.com" in results
        
        # Check that subprocess was called correctly
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "subfinder" in call_args
        assert "-d" in call_args
        assert "example.com" in call_args
    
    @patch('subprocess.run')
    def test_run_subfinder_failure(self, mock_run):
        """Test subfinder execution failure."""
        # Mock failed subprocess run
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: DNS resolution failed"
        mock_run.return_value = mock_result
        
        results = self.tools.run_subfinder("invalid-domain.com")
        
        assert len(results) == 0
    
    @patch('subprocess.run')
    def test_run_httpx_success(self, mock_run):
        """Test successful httpx execution."""
        # Mock successful subprocess run with JSON output
        httpx_output = [
            {
                "url": "https://example.com",
                "status_code": 200,
                "title": "Example Domain",
                "content_length": 1256,
                "technologies": ["nginx"]
            },
            {
                "url": "https://sub.example.com",
                "status_code": 404,
                "title": "Not Found",
                "content_length": 162
            }
        ]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "\n".join([json.dumps(item) for item in httpx_output])
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        targets = ["example.com", "sub.example.com"]
        results = self.tools.run_httpx(targets)
        
        assert len(results) == 2
        assert results[0]["url"] == "https://example.com"
        assert results[0]["status_code"] == 200
        assert results[1]["status_code"] == 404
    
    @patch('subprocess.run')
    def test_run_nuclei_success(self, mock_run):
        """Test successful nuclei execution."""
        # Mock successful subprocess run with JSON output
        nuclei_output = [
            {
                "template-id": "http-missing-security-headers",
                "info": {
                    "name": "HTTP Missing Security Headers",
                    "severity": "info",
                    "description": "Missing security headers detected"
                },
                "matched-at": "https://example.com",
                "type": "http"
            },
            {
                "template-id": "ssl-dns-names",
                "info": {
                    "name": "SSL DNS Names",
                    "severity": "info",
                    "description": "Extract DNS names from SSL certificate"
                },
                "matched-at": "https://example.com:443",
                "type": "ssl"
            }
        ]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "\n".join([json.dumps(item) for item in nuclei_output])
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        targets = ["https://example.com"]
        findings = self.tools.run_nuclei(targets)
        
        assert len(findings) == 2
        assert findings[0].title == "HTTP Missing Security Headers"
        assert findings[0].severity == SeverityLevel.INFO
        assert findings[0].target == "https://example.com"
        assert findings[0].tool == "nuclei"
    
    @patch('subprocess.run')
    def test_run_nuclei_with_filtering(self, mock_run):
        """Test nuclei execution with scope filtering."""
        # Mock nuclei output with both in-scope and out-of-scope results
        nuclei_output = [
            {
                "template-id": "test-template",
                "info": {
                    "name": "Test Finding",
                    "severity": "medium",
                    "description": "Test description"
                },
                "matched-at": "https://example.com",  # In scope
                "type": "http"
            },
            {
                "template-id": "test-template-2",
                "info": {
                    "name": "Test Finding 2",
                    "severity": "high",
                    "description": "Test description 2"
                },
                "matched-at": "https://outofscope.com",  # Out of scope
                "type": "http"
            }
        ]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "\n".join([json.dumps(item) for item in nuclei_output])
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        targets = ["https://example.com", "https://outofscope.com"]
        findings = self.tools.run_nuclei(targets)
        
        # Should only return the in-scope finding
        assert len(findings) == 1
        assert findings[0].target == "https://example.com"
    
    def test_parse_nuclei_severity(self):
        """Test nuclei severity parsing."""
        assert self.tools._parse_nuclei_severity("critical") == SeverityLevel.CRITICAL
        assert self.tools._parse_nuclei_severity("high") == SeverityLevel.HIGH
        assert self.tools._parse_nuclei_severity("medium") == SeverityLevel.MEDIUM
        assert self.tools._parse_nuclei_severity("low") == SeverityLevel.LOW
        assert self.tools._parse_nuclei_severity("info") == SeverityLevel.INFO
        assert self.tools._parse_nuclei_severity("unknown") == SeverityLevel.INFO
    
    def test_extract_target_from_url(self):
        """Test target extraction from URLs."""
        assert self.tools._extract_target_from_url("https://example.com") == "example.com"
        assert self.tools._extract_target_from_url("https://sub.example.com:8080") == "sub.example.com"
        assert self.tools._extract_target_from_url("http://192.168.1.1/path") == "192.168.1.1"
        assert self.tools._extract_target_from_url("invalid-url") == "invalid-url"


class TestBurpSuiteParser:
    """Test BurpSuiteParser class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scope = Scope(
            included=[ScopeTarget(type="domain", value="example.com")],
            excluded=[]
        )
        self.scope_validator = ScopeValidator(self.scope)
        self.parser = BurpSuiteParser(self.scope_validator)
    
    def test_parse_xml_export(self):
        """Test parsing Burp XML export."""
        xml_content = '''
        <?xml version="1.0"?>
        <issues>
            <issue>
                <serialNumber>1</serialNumber>
                <type>1048832</type>
                <name>SQL injection</name>
                <host>https://example.com</host>
                <path>/login</path>
                <location>POST parameter 'username'</location>
                <severity>High</severity>
                <confidence>Certain</confidence>
                <issueBackground>SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries in an unsafe manner.</issueBackground>
                <remediationBackground>The most effective way to prevent SQL injection attacks is to use parameterized queries.</remediationBackground>
                <issueDetail>The application appears to be vulnerable to SQL injection attacks.</issueDetail>
                <remediationDetail>Use parameterized queries for all database operations.</remediationDetail>
            </issue>
            <issue>
                <serialNumber>2</serialNumber>
                <type>2097408</type>
                <name>Cross-site scripting (reflected)</name>
                <host>https://outofscope.com</host>
                <path>/search</path>
                <location>GET parameter 'q'</location>
                <severity>Medium</severity>
                <confidence>Firm</confidence>
                <issueBackground>Reflected cross-site scripting vulnerabilities arise when data is copied from a request and echoed into the application's immediate response in an unsafe way.</issueBackground>
                <issueDetail>The application reflects user input without proper encoding.</issueDetail>
            </issue>
        </issues>
        '''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(xml_content)
            temp_path = f.name
        
        try:
            findings = self.parser.parse_xml_export(temp_path)
            
            # Should only return the in-scope finding
            assert len(findings) == 1
            finding = findings[0]
            assert finding.title == "SQL injection"
            assert finding.severity == SeverityLevel.HIGH
            assert finding.target == "https://example.com/login"
            assert finding.tool == "burp"
            assert "SQL injection vulnerabilities" in finding.description
        finally:
            Path(temp_path).unlink()
    
    def test_parse_json_export(self):
        """Test parsing Burp JSON export."""
        json_content = {
            "issues": [
                {
                    "type": "SQL injection",
                    "name": "SQL injection vulnerability",
                    "host": "example.com",
                    "path": "/api/users",
                    "severity": "High",
                    "confidence": "Certain",
                    "description": "SQL injection found in API endpoint",
                    "background": "SQL injection background info",
                    "remediation": "Use parameterized queries"
                },
                {
                    "type": "XSS",
                    "name": "Cross-site scripting",
                    "host": "outofscope.com",
                    "path": "/search",
                    "severity": "Medium",
                    "confidence": "Firm",
                    "description": "XSS vulnerability found"
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(json_content, f)
            temp_path = f.name
        
        try:
            findings = self.parser.parse_json_export(temp_path)
            
            # Should only return the in-scope finding
            assert len(findings) == 1
            finding = findings[0]
            assert finding.title == "SQL injection vulnerability"
            assert finding.severity == SeverityLevel.HIGH
            assert finding.target == "example.com/api/users"
            assert finding.tool == "burp"
        finally:
            Path(temp_path).unlink()
    
    def test_normalize_severity(self):
        """Test severity normalization."""
        assert self.parser._normalize_severity("Critical") == SeverityLevel.CRITICAL
        assert self.parser._normalize_severity("High") == SeverityLevel.HIGH
        assert self.parser._normalize_severity("Medium") == SeverityLevel.MEDIUM
        assert self.parser._normalize_severity("Low") == SeverityLevel.LOW
        assert self.parser._normalize_severity("Information") == SeverityLevel.INFO
        assert self.parser._normalize_severity("Info") == SeverityLevel.INFO
        assert self.parser._normalize_severity("Unknown") == SeverityLevel.INFO
    
    def test_normalize_confidence(self):
        """Test confidence normalization."""
        assert self.parser._normalize_confidence("Certain") == 1.0
        assert self.parser._normalize_confidence("Firm") == 0.8
        assert self.parser._normalize_confidence("Tentative") == 0.5
        assert self.parser._normalize_confidence("Unknown") == 0.3
    
    def test_burp_issue_to_finding(self):
        """Test converting BurpIssue to Finding."""
        burp_issue = BurpIssue(
            type="SQL injection",
            name="SQL injection vulnerability",
            host="example.com",
            path="/login",
            severity="High",
            confidence="Certain",
            description="SQL injection found in login form",
            background="Background information",
            remediation="Use parameterized queries"
        )
        
        finding = self.parser._burp_issue_to_finding(burp_issue)
        
        assert finding.title == "SQL injection vulnerability"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == 1.0
        assert finding.target == "example.com/login"
        assert finding.tool == "burp"
        assert "SQL injection found" in finding.description
        assert "Background information" in finding.description
        assert "Use parameterized queries" in finding.description
    
    def test_filter_by_scope(self):
        """Test filtering findings by scope."""
        findings = [
            Finding(
                id="1",
                title="In Scope Finding",
                description="Test",
                severity=SeverityLevel.HIGH,
                confidence=0.9,
                target="example.com",
                tool="burp"
            ),
            Finding(
                id="2",
                title="Out of Scope Finding",
                description="Test",
                severity=SeverityLevel.MEDIUM,
                confidence=0.8,
                target="outofscope.com",
                tool="burp"
            )
        ]
        
        filtered = self.parser._filter_by_scope(findings)
        
        assert len(filtered) == 1
        assert filtered[0].title == "In Scope Finding"
        assert filtered[0].target == "example.com"
    
    def test_parse_invalid_file(self):
        """Test parsing invalid file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("This is not valid XML or JSON")
            temp_path = f.name
        
        try:
            # Should raise exception for invalid XML
            with pytest.raises(Exception):
                self.parser.parse_xml_export(temp_path)
            
            # Should raise exception for invalid JSON
            with pytest.raises(Exception):
                self.parser.parse_json_export(temp_path)
        finally:
            Path(temp_path).unlink()
    
    def test_parse_nonexistent_file(self):
        """Test parsing nonexistent file."""
        with pytest.raises(FileNotFoundError):
            self.parser.parse_xml_export("/nonexistent/file.xml")
        
        with pytest.raises(FileNotFoundError):
            self.parser.parse_json_export("/nonexistent/file.json")