"""Pytest configuration and shared fixtures."""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch
from datetime import datetime

from redteam_automation.schemas import (
    ScopeTarget, Scope, Finding, ScanResult, EngagementReport,
    SeverityLevel, FindingStatus, ToolType
)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    if Path(temp_path).exists():
        shutil.rmtree(temp_path)


@pytest.fixture
def sample_scope():
    """Create a sample scope for testing."""
    return Scope(
        included_targets=[
            ScopeTarget(type="domain", value="example.com"),
            ScopeTarget(type="ip", value="192.168.1.0/24"),
            ScopeTarget(type="url", value="https://api.example.com")
        ],
        excluded_targets=[
            ScopeTarget(type="domain", value="admin.example.com"),
            ScopeTarget(type="ip", value="192.168.1.1")
        ]
    )


@pytest.fixture
def sample_scope_yaml(temp_dir):
    """Create a sample scope.yaml file."""
    scope_content = """
included_targets:
  - type: domain
    value: example.com
  - type: ip
    value: 192.168.1.0/24
  - type: url
    value: https://api.example.com

excluded_targets:
  - type: domain
    value: admin.example.com
  - type: ip
    value: 192.168.1.1
"""
    scope_file = temp_dir / "scope.yaml"
    scope_file.write_text(scope_content)
    return scope_file


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        Finding(
            id="finding-1",
            title="SQL Injection",
            description="SQL injection vulnerability found",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            target="https://example.com/login",
            tool="nuclei",
            status=FindingStatus.TRUE_POSITIVE,
            references=["https://owasp.org/www-community/attacks/SQL_Injection"]
        ),
        Finding(
            id="finding-2",
            title="XSS Vulnerability",
            description="Cross-site scripting vulnerability",
            severity=SeverityLevel.MEDIUM,
            confidence=0.8,
            target="https://example.com/search",
            tool="burp",
            status=FindingStatus.TRUE_POSITIVE
        ),
        Finding(
            id="finding-3",
            title="Information Disclosure",
            description="Sensitive information exposed",
            severity=SeverityLevel.LOW,
            confidence=0.6,
            target="https://example.com/info",
            tool="nuclei",
            status=FindingStatus.FALSE_POSITIVE
        )
    ]


@pytest.fixture
def sample_scan_results():
    """Create sample scan results for testing."""
    return [
        ScanResult(
            tool="subfinder",
            target="example.com",
            status="completed",
            findings_count=10,
            timestamp=datetime.now()
        ),
        ScanResult(
            tool="nuclei",
            target="example.com",
            status="completed",
            findings_count=2,
            timestamp=datetime.now()
        ),
        ScanResult(
            tool="httpx",
            target="example.com",
            status="failed",
            findings_count=0,
            error="Connection timeout",
            timestamp=datetime.now()
        )
    ]


@pytest.fixture
def sample_engagement_report(sample_findings, sample_scan_results):
    """Create a sample engagement report."""
    return EngagementReport(
        id="test-engagement-123",
        target_scope="example.com",
        findings=sample_findings,
        scan_results=sample_scan_results,
        created_at=datetime.now(),
        completed_at=datetime.now(),
        summary="Test engagement completed successfully",
        recommendations=[
            "Fix SQL injection vulnerabilities",
            "Implement input validation",
            "Add security headers"
        ]
    )


@pytest.fixture
def mock_security_agent():
    """Create a mock security agent."""
    agent = Mock()
    agent.triage_finding.return_value = {
        "severity": "high",
        "confidence": 0.9,
        "status": "true_positive",
        "reasoning": "This is a valid security finding"
    }
    agent.extract_knowledge.return_value = [
        {
            "technique": "SQL Injection",
            "description": "Injection attack technique",
            "mitigation": "Use parameterized queries"
        }
    ]
    agent.generate_insights.return_value = {
        "summary": "Multiple vulnerabilities found",
        "recommendations": ["Implement security controls"]
    }
    return agent


@pytest.fixture
def mock_vector_store():
    """Create a mock vector store."""
    store = Mock()
    store.add_knowledge_entry.return_value = None
    store.add_finding.return_value = None
    store.add_insight.return_value = None
    store.search_knowledge.return_value = [
        {
            "technique": "SQL Injection",
            "description": "Database injection attack",
            "score": 0.95
        }
    ]
    store.search_findings.return_value = [
        {
            "title": "Similar SQL Injection",
            "target": "other.example.com",
            "score": 0.88
        }
    ]
    return store


@pytest.fixture
def mock_subprocess_run():
    """Mock subprocess.run for tool execution tests."""
    with patch('subprocess.run') as mock_run:
        # Default successful response
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = '{"host": "example.com"}'
        mock_run.return_value.stderr = ''
        yield mock_run


@pytest.fixture
def mock_gemini_model():
    """Mock Google Gemini model."""
    with patch('google.generativeai.GenerativeModel') as mock_model:
        mock_instance = Mock()
        mock_response = Mock()
        mock_response.text = '{"status": "success", "result": "test response"}'
        mock_instance.generate_content.return_value = mock_response
        mock_model.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_chroma_client():
    """Mock ChromaDB client."""
    with patch('chromadb.Client') as mock_client:
        mock_instance = Mock()
        mock_collection = Mock()
        mock_collection.add.return_value = None
        mock_collection.query.return_value = {
            'documents': [['test document']],
            'metadatas': [[{'technique': 'test'}]],
            'distances': [[0.1]]
        }
        mock_instance.get_or_create_collection.return_value = mock_collection
        mock_client.return_value = mock_instance
        yield mock_instance


@pytest.fixture(autouse=True)
def mock_settings():
    """Mock settings for all tests."""
    with patch('redteam_automation.config.settings') as mock_settings:
        mock_settings.GOOGLE_API_KEY = "test-api-key"
        mock_settings.OUTPUT_DIR = "/tmp/test_output"
        mock_settings.CHROMA_PERSIST_DIR = "/tmp/test_chroma"
        mock_settings.MAX_CONCURRENT_SCANS = 5
        mock_settings.RATE_LIMIT_DELAY = 1.0
        mock_settings.SCOPE_FILE = "scope.yaml"
        mock_settings.STEPS_LOG_FILE = "steps.txt"
        yield mock_settings


@pytest.fixture
def burp_xml_content():
    """Sample Burp Suite XML export content."""
    return '''
<?xml version="1.0"?>
<issues burpVersion="2023.10.3.4" exportTime="Wed Nov 15 10:30:00 UTC 2023">
  <issue>
    <serialNumber>1</serialNumber>
    <type>1048832</type>
    <name>SQL injection</name>
    <host ip="192.168.1.100">https://example.com</host>
    <path><![CDATA[/login]]></path>
    <location><![CDATA[/login]]></location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground><![CDATA[SQL injection vulnerability found in login form]]></issueBackground>
    <remediationBackground><![CDATA[Use parameterized queries]]></remediationBackground>
    <issueDetail><![CDATA[The application is vulnerable to SQL injection]]></issueDetail>
    <remediationDetail><![CDATA[Implement proper input validation]]></remediationDetail>
    <requestresponse>
      <request base64="true"><![CDATA[R0VUIC9sb2dpbiBIVFRQLzEuMQ==]]></request>
      <response base64="true"><![CDATA[SFRUUC8xLjEgMjAwIE9L]]></response>
    </requestresponse>
  </issue>
  <issue>
    <serialNumber>2</serialNumber>
    <type>2097408</type>
    <name>Cross-site scripting (reflected)</name>
    <host ip="192.168.1.100">https://example.com</host>
    <path><![CDATA[/search]]></path>
    <location><![CDATA[/search?q=test]]></location>
    <severity>Medium</severity>
    <confidence>Firm</confidence>
    <issueBackground><![CDATA[XSS vulnerability in search parameter]]></issueBackground>
    <issueDetail><![CDATA[User input is reflected without proper encoding]]></issueDetail>
  </issue>
</issues>
'''


@pytest.fixture
def burp_json_content():
    """Sample Burp Suite JSON export content."""
    return {
        "issues": [
            {
                "serialNumber": 1,
                "type": 1048832,
                "name": "SQL injection",
                "host": "https://example.com",
                "path": "/login",
                "severity": "High",
                "confidence": "Certain",
                "issueBackground": "SQL injection vulnerability found",
                "issueDetail": "The application is vulnerable to SQL injection"
            },
            {
                "serialNumber": 2,
                "type": 2097408,
                "name": "Cross-site scripting (reflected)",
                "host": "https://example.com",
                "path": "/search",
                "severity": "Medium",
                "confidence": "Firm",
                "issueBackground": "XSS vulnerability in search parameter",
                "issueDetail": "User input is reflected without proper encoding"
            }
        ]
    }


# Test markers for different test categories
pytestmark = [
    pytest.mark.asyncio,  # For async tests if needed
]


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "external: mark test as requiring external dependencies"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test names."""
    for item in items:
        # Add unit marker to most tests by default
        if not any(marker.name in ['integration', 'slow', 'external'] 
                  for marker in item.iter_markers()):
            item.add_marker(pytest.mark.unit)
        
        # Add slow marker to tests that might be slow
        if any(keyword in item.name.lower() 
               for keyword in ['pdf', 'report', 'large', 'bulk']):
            item.add_marker(pytest.mark.slow)
        
        # Add external marker to tests requiring external tools
        if any(keyword in item.name.lower() 
               for keyword in ['nuclei', 'subfinder', 'httpx', 'burp']):
            item.add_marker(pytest.mark.external)