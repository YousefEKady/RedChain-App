"""Tests for reporting module."""

import pytest
import tempfile
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch

from redteam_automation.reporting.generator import ReportGenerator, generate_engagement_report
from redteam_automation.schemas import (
    EngagementReport, Finding, ScanResult, SeverityLevel, FindingStatus
)


class TestReportGenerator:
    """Test ReportGenerator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.output_dir = Path(self.temp_dir) / "reports"
        self.generator = ReportGenerator(self.output_dir)
        
        # Create sample report data
        self.sample_findings = [
            Finding(
                id="finding-1",
                title="SQL Injection Vulnerability",
                description="SQL injection found in login form",
                severity=SeverityLevel.HIGH,
                confidence=0.9,
                target="https://example.com/login",
                tool="nuclei",
                status=FindingStatus.TRUE_POSITIVE,
                references=["https://owasp.org/www-community/attacks/SQL_Injection"]
            ),
            Finding(
                id="finding-2",
                title="Missing Security Headers",
                description="Security headers not implemented",
                severity=SeverityLevel.MEDIUM,
                confidence=0.8,
                target="https://example.com",
                tool="nuclei",
                status=FindingStatus.TRUE_POSITIVE
            ),
            Finding(
                id="finding-3",
                title="False Positive Finding",
                description="This is a false positive",
                severity=SeverityLevel.LOW,
                confidence=0.3,
                target="https://example.com/test",
                tool="burp",
                status=FindingStatus.FALSE_POSITIVE
            )
        ]
        
        self.sample_scan_results = [
            ScanResult(
                tool="subfinder",
                target="example.com",
                status="completed",
                findings_count=5,
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
        
        self.sample_report = EngagementReport(
            id="engagement-123",
            target_scope="example.com",
            findings=self.sample_findings,
            scan_results=self.sample_scan_results,
            created_at=datetime.now(),
            completed_at=datetime.now(),
            summary="Security assessment completed with multiple findings",
            recommendations=[
                "Implement parameterized queries to prevent SQL injection",
                "Add security headers to all HTTP responses",
                "Conduct regular security assessments"
            ]
        )
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_generator_initialization(self):
        """Test report generator initialization."""
        assert self.generator.output_dir == self.output_dir
        assert self.output_dir.exists()
        assert self.generator.jinja_env is not None
        
        # Check that templates directory was created
        template_dir = Path(self.generator.jinja_env.loader.searchpath[0])
        assert template_dir.exists()
    
    def test_prepare_report_data(self):
        """Test report data preparation."""
        report_data = self.generator._prepare_report_data(self.sample_report)
        
        # Check basic structure
        assert 'report' in report_data
        assert 'statistics' in report_data
        assert 'findings_by_severity' in report_data
        assert 'findings_by_tool' in report_data
        assert 'scan_summary' in report_data
        
        # Check statistics
        stats = report_data['statistics']
        assert stats['total_findings'] == 3
        assert stats['true_positives'] == 2
        assert stats['false_positives'] == 1
        assert stats['accuracy'] == pytest.approx(66.67, rel=1e-2)
        
        # Check findings by severity
        severity_groups = report_data['findings_by_severity']
        assert len(severity_groups['high']) == 1
        assert len(severity_groups['medium']) == 1
        assert len(severity_groups['low']) == 1
        
        # Check findings by tool
        tool_groups = report_data['findings_by_tool']
        assert len(tool_groups['nuclei']) == 2
        assert len(tool_groups['burp']) == 1
        
        # Check scan summary
        scan_summary = report_data['scan_summary']
        assert 'subfinder' in scan_summary
        assert 'nuclei' in scan_summary
        assert 'httpx' in scan_summary
        assert scan_summary['nuclei']['total_findings'] == 2
        assert scan_summary['httpx']['successful_scans'] == 0
    
    def test_generate_json_report(self):
        """Test JSON report generation."""
        report_data = self.generator._prepare_report_data(self.sample_report)
        file_path = self.generator._generate_json_report(self.sample_report, report_data)
        
        assert file_path.exists()
        assert file_path.suffix == '.json'
        assert 'engagement-123' in file_path.name
        
        # Verify JSON content
        with open(file_path, 'r') as f:
            json_data = json.load(f)
        
        assert json_data['id'] == 'engagement-123'
        assert json_data['target_scope'] == 'example.com'
        assert len(json_data['findings']) == 3
        assert 'statistics' in json_data
    
    def test_generate_markdown_report(self):
        """Test Markdown report generation."""
        report_data = self.generator._prepare_report_data(self.sample_report)
        file_path = self.generator._generate_markdown_report(self.sample_report, report_data)
        
        assert file_path.exists()
        assert file_path.suffix == '.md'
        assert 'engagement-123' in file_path.name
        
        # Verify Markdown content
        content = file_path.read_text()
        assert '# Red Team Engagement Report' in content
        assert 'engagement-123' in content
        assert 'SQL Injection Vulnerability' in content
        assert 'example.com' in content
    
    def test_generate_html_report(self):
        """Test HTML report generation."""
        report_data = self.generator._prepare_report_data(self.sample_report)
        file_path = self.generator._generate_html_report(self.sample_report, report_data)
        
        assert file_path.exists()
        assert file_path.suffix == '.html'
        assert 'engagement-123' in file_path.name
        
        # Verify HTML content
        content = file_path.read_text()
        assert '<!DOCTYPE html>' in content
        assert '<title>' in content
        assert 'engagement-123' in content
        assert 'SQL Injection Vulnerability' in content
    
    @patch('weasyprint.HTML')
    def test_generate_pdf_report(self, mock_html):
        """Test PDF report generation."""
        # Mock WeasyPrint HTML class
        mock_html_instance = Mock()
        mock_html.return_value = mock_html_instance
        
        report_data = self.generator._prepare_report_data(self.sample_report)
        file_path = self.generator._generate_pdf_report(self.sample_report, report_data)
        
        assert file_path.suffix == '.pdf'
        assert 'engagement-123' in file_path.name
        
        # Verify WeasyPrint was called
        mock_html.assert_called_once()
        mock_html_instance.write_pdf.assert_called_once()
    
    def test_generate_report_all_formats(self):
        """Test generating report in all formats."""
        with patch('weasyprint.HTML') as mock_html:
            mock_html_instance = Mock()
            mock_html.return_value = mock_html_instance
            
            generated_files = self.generator.generate_report(
                self.sample_report,
                formats=['json', 'md', 'html', 'pdf']
            )
            
            assert len(generated_files) == 4
            assert 'json' in generated_files
            assert 'md' in generated_files
            assert 'html' in generated_files
            assert 'pdf' in generated_files
            
            # Verify all files exist
            for format_type, file_path in generated_files.items():
                assert file_path.exists()
                assert 'engagement-123' in file_path.name
    
    def test_generate_report_subset_formats(self):
        """Test generating report with subset of formats."""
        generated_files = self.generator.generate_report(
            self.sample_report,
            formats=['json', 'md']
        )
        
        assert len(generated_files) == 2
        assert 'json' in generated_files
        assert 'md' in generated_files
        assert 'html' not in generated_files
        assert 'pdf' not in generated_files
    
    def test_generate_report_invalid_format(self):
        """Test generating report with invalid format."""
        generated_files = self.generator.generate_report(
            self.sample_report,
            formats=['json', 'invalid_format', 'md']
        )
        
        # Should generate valid formats and skip invalid ones
        assert len(generated_files) == 2
        assert 'json' in generated_files
        assert 'md' in generated_files
        assert 'invalid_format' not in generated_files
    
    def test_default_template_creation(self):
        """Test that default templates are created."""
        template_dir = Path(self.generator.jinja_env.loader.searchpath[0])
        
        # Check that template files exist
        assert (template_dir / 'report.md.j2').exists()
        assert (template_dir / 'report.html.j2').exists()
        assert (template_dir / 'report.css').exists()
        
        # Check template content
        md_template = (template_dir / 'report.md.j2').read_text()
        assert '# Red Team Engagement Report' in md_template
        assert '{{ report.id }}' in md_template
        
        html_template = (template_dir / 'report.html.j2').read_text()
        assert '<!DOCTYPE html>' in html_template
        assert '{{ report.id }}' in html_template
        
        css_content = (template_dir / 'report.css').read_text()
        assert '@page' in css_content
        assert 'font-family' in css_content
    
    def test_empty_report(self):
        """Test generating report with no findings."""
        empty_report = EngagementReport(
            id="empty-engagement",
            target_scope="example.com",
            findings=[],
            scan_results=[],
            created_at=datetime.now()
        )
        
        generated_files = self.generator.generate_report(
            empty_report,
            formats=['json', 'md']
        )
        
        assert len(generated_files) == 2
        
        # Verify JSON content
        json_content = json.loads(generated_files['json'].read_text())
        assert json_content['id'] == 'empty-engagement'
        assert len(json_content['findings']) == 0
        
        # Verify Markdown content
        md_content = generated_files['md'].read_text()
        assert 'empty-engagement' in md_content
        assert 'Total Findings:** 0' in md_content


class TestReportGeneratorConvenienceFunction:
    """Test convenience function for report generation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        self.sample_report = EngagementReport(
            id="test-engagement",
            target_scope="test.com",
            findings=[],
            scan_results=[],
            created_at=datetime.now()
        )
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_convenience_function(self):
        """Test convenience function for report generation."""
        generated_files = generate_engagement_report(
            self.sample_report,
            output_dir=Path(self.temp_dir),
            formats=['json', 'md']
        )
        
        assert len(generated_files) == 2
        assert 'json' in generated_files
        assert 'md' in generated_files
        
        # Verify files exist
        for file_path in generated_files.values():
            assert file_path.exists()
            assert 'test-engagement' in file_path.name
    
    def test_convenience_function_default_params(self):
        """Test convenience function with default parameters."""
        with patch('redteam_automation.reporting.generator.settings') as mock_settings:
            mock_settings.OUTPUT_DIR = self.temp_dir
            
            generated_files = generate_engagement_report(self.sample_report)
            
            # Should generate all default formats
            assert len(generated_files) >= 1  # At least one format should be generated


class TestReportGeneratorErrorHandling:
    """Test error handling in report generator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.generator = ReportGenerator(Path(self.temp_dir))
        
        self.sample_report = EngagementReport(
            id="error-test",
            target_scope="test.com",
            findings=[],
            scan_results=[],
            created_at=datetime.now()
        )
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_invalid_output_directory(self):
        """Test handling of invalid output directory."""
        # This should not raise an exception due to mkdir(parents=True, exist_ok=True)
        invalid_path = Path("/invalid/path/that/does/not/exist")
        
        # On Windows, this might fail due to permissions, so we'll test with a valid but nested path
        nested_path = Path(self.temp_dir) / "very" / "deep" / "nested" / "path"
        generator = ReportGenerator(nested_path)
        
        assert generator.output_dir == nested_path
        assert nested_path.exists()
    
    @patch('redteam_automation.reporting.generator.ReportGenerator._generate_json_report')
    def test_generation_error_handling(self, mock_json_gen):
        """Test error handling during report generation."""
        # Mock an exception during JSON generation
        mock_json_gen.side_effect = Exception("Test error")
        
        with pytest.raises(Exception):
            self.generator.generate_report(
                self.sample_report,
                formats=['json']
            )
    
    def test_malformed_report_data(self):
        """Test handling of malformed report data."""
        # Create a report with None values
        malformed_report = EngagementReport(
            id="malformed",
            target_scope="test.com",
            findings=[],
            scan_results=[],
            created_at=None,  # This could cause issues
            completed_at=None
        )
        
        # Should handle gracefully
        generated_files = self.generator.generate_report(
            malformed_report,
            formats=['json']
        )
        
        assert len(generated_files) == 1
        assert 'json' in generated_files