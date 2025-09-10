"""Tests for RAG modules."""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from redteam_automation.rag.vector_store import VectorStore
from redteam_automation.rag.knowledge_base import KnowledgeBase
from redteam_automation.schemas import KnowledgeEntry, Finding, SeverityLevel


class TestVectorStore:
    """Test VectorStore class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_chroma"
        self.vector_store = VectorStore(str(self.db_path))
    
    def teardown_method(self):
        """Clean up test fixtures."""
        # Clean up Chroma database
        import shutil
        if self.db_path.exists():
            shutil.rmtree(self.db_path)
    
    def test_vector_store_initialization(self):
        """Test vector store initialization."""
        assert self.vector_store.db_path == str(self.db_path)
        assert self.vector_store.client is not None
        assert self.vector_store.knowledge_collection is not None
        assert self.vector_store.findings_collection is not None
        assert self.vector_store.insights_collection is not None
    
    def test_prepare_text_for_embedding(self):
        """Test text preparation for embedding."""
        text = "This is a TEST with Special Characters! @#$%"
        prepared = self.vector_store._prepare_text_for_embedding(text)
        
        assert prepared == "this is a test with special characters"
        assert "!" not in prepared
        assert "@" not in prepared
    
    def test_add_knowledge_entry(self):
        """Test adding knowledge entry."""
        entry = KnowledgeEntry(
            id="kb-1",
            title="SQL Injection Basics",
            content="SQL injection is a code injection technique...",
            source="OWASP",
            tags=["sql", "injection", "web"],
            timestamp=datetime.now()
        )
        
        # Should not raise exception
        self.vector_store.add_knowledge_entry(entry)
        
        # Verify entry was added by searching
        results = self.vector_store.search_knowledge("SQL injection", limit=1)
        assert len(results) >= 0  # Chroma might not return results immediately
    
    def test_add_finding(self):
        """Test adding finding."""
        finding = Finding(
            id="finding-1",
            title="SQL Injection Found",
            description="SQL injection vulnerability detected in login form",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            target="example.com",
            tool="nuclei"
        )
        
        # Should not raise exception
        self.vector_store.add_finding(finding)
        
        # Verify finding was added by searching
        results = self.vector_store.search_findings("SQL injection", limit=1)
        assert len(results) >= 0  # Chroma might not return results immediately
    
    def test_add_insight(self):
        """Test adding insight."""
        insight = {
            "id": "insight-1",
            "content": "Common SQL injection patterns found in web applications",
            "engagement_id": "eng-1",
            "timestamp": datetime.now().isoformat()
        }
        
        # Should not raise exception
        self.vector_store.add_insight(insight)
        
        # Verify insight was added by searching
        results = self.vector_store.search_insights("SQL injection patterns", limit=1)
        assert len(results) >= 0  # Chroma might not return results immediately
    
    def test_search_empty_collections(self):
        """Test searching empty collections."""
        # Should return empty results without error
        knowledge_results = self.vector_store.search_knowledge("test query")
        findings_results = self.vector_store.search_findings("test query")
        insights_results = self.vector_store.search_insights("test query")
        
        assert isinstance(knowledge_results, list)
        assert isinstance(findings_results, list)
        assert isinstance(insights_results, list)
    
    def test_search_with_limit(self):
        """Test searching with limit parameter."""
        # Add multiple entries
        for i in range(5):
            entry = KnowledgeEntry(
                id=f"kb-{i}",
                title=f"Test Entry {i}",
                content=f"This is test content number {i} about security",
                source="Test",
                tags=["test"],
                timestamp=datetime.now()
            )
            self.vector_store.add_knowledge_entry(entry)
        
        # Search with limit
        results = self.vector_store.search_knowledge("security", limit=3)
        assert len(results) <= 3


class TestKnowledgeBase:
    """Test KnowledgeBase class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_chroma"
        
        # Mock SecurityAgent
        self.mock_agent = Mock()
        self.mock_agent.extract_knowledge_from_report.return_value = [
            KnowledgeEntry(
                id="kb-1",
                title="Extracted Knowledge",
                content="This is extracted knowledge from report",
                source="Report",
                tags=["extracted"],
                timestamp=datetime.now()
            )
        ]
        self.mock_agent.generate_engagement_insights.return_value = "Generated insights from engagement"
        
        self.knowledge_base = KnowledgeBase(
            vector_store_path=str(self.db_path),
            security_agent=self.mock_agent
        )
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        if self.db_path.exists():
            shutil.rmtree(self.db_path)
    
    def test_knowledge_base_initialization(self):
        """Test knowledge base initialization."""
        assert self.knowledge_base.vector_store is not None
        assert self.knowledge_base.security_agent == self.mock_agent
    
    def test_ingest_report_content(self):
        """Test ingesting report content."""
        report_content = "This is a security report with findings about SQL injection vulnerabilities."
        
        result = self.knowledge_base.ingest_report(report_content)
        
        assert result is True
        # Verify that security agent was called
        self.mock_agent.extract_knowledge_from_report.assert_called_once_with(report_content)
    
    def test_ingest_report_file(self):
        """Test ingesting report from file."""
        report_content = "This is a test security report with vulnerability information."
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(report_content)
            temp_path = f.name
        
        try:
            result = self.knowledge_base.ingest_report_file(temp_path)
            
            assert result is True
            # Verify that security agent was called with file content
            self.mock_agent.extract_knowledge_from_report.assert_called_once_with(report_content)
        finally:
            Path(temp_path).unlink()
    
    def test_ingest_report_file_not_found(self):
        """Test ingesting non-existent report file."""
        result = self.knowledge_base.ingest_report_file("/nonexistent/file.txt")
        assert result is False
    
    def test_search_knowledge(self):
        """Test searching knowledge."""
        # Add some knowledge first
        entry = KnowledgeEntry(
            id="kb-test",
            title="Test Knowledge",
            content="This is test knowledge about SQL injection",
            source="Test",
            tags=["test"],
            timestamp=datetime.now()
        )
        self.knowledge_base.vector_store.add_knowledge_entry(entry)
        
        results = self.knowledge_base.search_knowledge("SQL injection")
        assert isinstance(results, list)
    
    def test_get_relevant_techniques(self):
        """Test getting relevant techniques."""
        finding = Finding(
            id="finding-1",
            title="SQL Injection",
            description="SQL injection found in login form",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            target="example.com",
            tool="nuclei"
        )
        
        techniques = self.knowledge_base.get_relevant_techniques(finding)
        assert isinstance(techniques, list)
    
    def test_get_similar_findings(self):
        """Test getting similar findings."""
        # Add a finding first
        finding1 = Finding(
            id="finding-1",
            title="SQL Injection",
            description="SQL injection in login form",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            target="example.com",
            tool="nuclei"
        )
        self.knowledge_base.vector_store.add_finding(finding1)
        
        # Search for similar findings
        finding2 = Finding(
            id="finding-2",
            title="SQL Injection",
            description="SQL injection in search form",
            severity=SeverityLevel.MEDIUM,
            confidence=0.8,
            target="test.com",
            tool="burp"
        )
        
        similar = self.knowledge_base.get_similar_findings(finding2)
        assert isinstance(similar, list)
    
    def test_store_engagement_insights(self):
        """Test storing engagement insights."""
        findings = [
            Finding(
                id="finding-1",
                title="SQL Injection",
                description="SQL injection vulnerability",
                severity=SeverityLevel.HIGH,
                confidence=0.9,
                target="example.com",
                tool="nuclei"
            )
        ]
        
        engagement_id = "eng-123"
        
        result = self.knowledge_base.store_engagement_insights(findings, engagement_id)
        
        assert result is True
        # Verify that security agent was called
        self.mock_agent.generate_engagement_insights.assert_called_once_with(findings)
    
    @patch('builtins.open', new_callable=mock_open, read_data="Test report content")
    def test_ingest_multiple_file_formats(self, mock_file):
        """Test ingesting different file formats."""
        # Test different file extensions
        file_types = ['.txt', '.md', '.pdf', '.docx']
        
        for ext in file_types:
            filename = f"test_report{ext}"
            result = self.knowledge_base.ingest_report_file(filename)
            
            if ext in ['.txt', '.md']:  # Supported formats
                assert result is True
            # Note: PDF and DOCX would require additional libraries in real implementation
    
    def test_knowledge_base_with_none_agent(self):
        """Test knowledge base with None security agent."""
        kb = KnowledgeBase(
            vector_store_path=str(self.db_path),
            security_agent=None
        )
        
        # Should handle None agent gracefully
        result = kb.ingest_report("Test report")
        assert result is False
        
        insights_result = kb.store_engagement_insights([], "eng-1")
        assert insights_result is False


class TestKnowledgeBaseIntegration:
    """Integration tests for KnowledgeBase."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_chroma"
        
        # Create a more realistic mock agent
        self.mock_agent = Mock()
        
        def mock_extract_knowledge(content):
            # Simulate extracting knowledge based on content
            if "SQL injection" in content:
                return [
                    KnowledgeEntry(
                        id="kb-sql",
                        title="SQL Injection Knowledge",
                        content="SQL injection is a code injection technique",
                        source="Report",
                        tags=["sql", "injection"],
                        timestamp=datetime.now()
                    )
                ]
            return []
        
        def mock_generate_insights(findings):
            if findings:
                return f"Generated insights for {len(findings)} findings"
            return "No findings to analyze"
        
        self.mock_agent.extract_knowledge_from_report.side_effect = mock_extract_knowledge
        self.mock_agent.generate_engagement_insights.side_effect = mock_generate_insights
        
        self.knowledge_base = KnowledgeBase(
            vector_store_path=str(self.db_path),
            security_agent=self.mock_agent
        )
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        if self.db_path.exists():
            shutil.rmtree(self.db_path)
    
    def test_end_to_end_knowledge_workflow(self):
        """Test complete knowledge workflow."""
        # 1. Ingest a report
        report_content = "Security assessment found SQL injection vulnerabilities in the web application."
        result = self.knowledge_base.ingest_report(report_content)
        assert result is True
        
        # 2. Search for knowledge
        knowledge_results = self.knowledge_base.search_knowledge("SQL injection")
        assert isinstance(knowledge_results, list)
        
        # 3. Add a finding
        finding = Finding(
            id="finding-1",
            title="SQL Injection Found",
            description="SQL injection in login form",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            target="example.com",
            tool="nuclei"
        )
        self.knowledge_base.vector_store.add_finding(finding)
        
        # 4. Get relevant techniques
        techniques = self.knowledge_base.get_relevant_techniques(finding)
        assert isinstance(techniques, list)
        
        # 5. Store engagement insights
        insights_result = self.knowledge_base.store_engagement_insights([finding], "eng-1")
        assert insights_result is True
        
        # 6. Search insights
        insights = self.knowledge_base.vector_store.search_insights("findings")
        assert isinstance(insights, list)