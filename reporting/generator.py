"""Report generation module for red team automation."""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, Template
import markdown

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
    HTML = CSS = None

from schemas import EngagementReport, Finding, ScanResult, SeverityLevel, FindingStatus
from utils.logging import get_logger
from config import settings

logger = get_logger(__name__)


class ReportGenerator:
    """Generate reports in multiple formats (MD, HTML, PDF)."""
    
    def __init__(self, output_dir: Optional[Path] = None):
        """Initialize the report generator.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir) if output_dir else Path(settings.OUTPUT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup Jinja2 environment
        template_dir = Path(__file__).parent / "templates"
        template_dir.mkdir(exist_ok=True)
        
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True
        )
        
        # Create default templates if they don't exist
        self._create_default_templates()
        
        logger.info("Report generator initialized", output_dir=str(self.output_dir))
    
    def _create_default_templates(self):
        """Create default report templates."""
        template_dir = Path(__file__).parent / "templates"
        
        # Markdown template
        md_template_path = template_dir / "report.md.j2"
        if not md_template_path.exists():
            md_template_content = self._get_default_markdown_template()
            md_template_path.write_text(md_template_content)
        
        # HTML template
        html_template_path = template_dir / "report.html.j2"
        if not html_template_path.exists():
            html_template_content = self._get_default_html_template()
            html_template_path.write_text(html_template_content)
        
        # CSS for PDF
        css_path = template_dir / "report.css"
        if not css_path.exists():
            css_content = self._get_default_css()
            css_path.write_text(css_content)
    
    def generate_report(
        self, 
        report: EngagementReport, 
        formats: list = None
    ) -> Dict[str, Path]:
        """Generate reports in specified formats.
        
        Args:
            report: Engagement report data
            formats: List of formats to generate ['md', 'html', 'pdf', 'json']
            
        Returns:
            Dictionary mapping format to file path
        """
        if formats is None:
            formats = ['md', 'html', 'pdf', 'json']
        
        generated_files = {}
        
        try:
            # Prepare report data for templates
            report_data = self._prepare_report_data(report)
            
            for format_type in formats:
                if format_type == 'json':
                    file_path = self._generate_json_report(report, report_data)
                elif format_type == 'md':
                    file_path = self._generate_markdown_report(report, report_data)
                elif format_type == 'html':
                    file_path = self._generate_html_report(report, report_data)
                elif format_type == 'pdf':
                    file_path = self._generate_pdf_report(report, report_data)
                else:
                    logger.warning("Unsupported format", format=format_type)
                    continue
                
                generated_files[format_type] = file_path
                logger.info("Report generated", format=format_type, path=str(file_path))
            
            return generated_files
            
        except Exception as e:
            logger.error("Report generation failed", error=str(e))
            raise
    
    def _prepare_report_data(self, report) -> Dict[str, Any]:
        """Prepare report data for template rendering.
        
        Args:
            report: Engagement report (can be EngagementReport object or dict)
            
        Returns:
            Dictionary with processed report data
        """
        # Handle both dictionary and object inputs
        if isinstance(report, dict):
            # If report is a dictionary, extract findings or use empty list
            findings = report.get('findings', [])
        else:
            # If report is an object, use the findings attribute
            findings = getattr(report, 'findings', [])
        
        # Calculate statistics
        total_findings = len(findings)
        true_positives = len([f for f in findings if getattr(f, 'status', None) == FindingStatus.TRUE_POSITIVE]) if findings else 0
        false_positives = len([f for f in findings if getattr(f, 'status', None) == FindingStatus.FALSE_POSITIVE]) if findings else 0
        high_priority_findings = len([f for f in findings if hasattr(f, 'priority_score') and getattr(f, 'priority_score', 0) > 0.7]) if findings else 0
        
        # Calculate average confidence (handle None values)
        confidence_values = [getattr(f, 'confidence', None) for f in findings if getattr(f, 'confidence', None) is not None] if findings else []
        avg_confidence = sum(confidence_values) / len(confidence_values) if confidence_values else None
        
        # Group findings by severity
        findings_by_severity = {}
        for severity in SeverityLevel:
            findings_by_severity[severity.value] = [
                f for f in findings if getattr(f, 'severity', None) == severity
            ]
        
        # Group findings by tool
        findings_by_tool = {}
        for finding in findings:
            tool = getattr(finding, 'tool', 'unknown')
            if tool not in findings_by_tool:
                findings_by_tool[tool] = []
            findings_by_tool[tool].append(finding)
        
        # Calculate duration
        duration = None
        if isinstance(report, dict):
            completed_at = report.get('completed_at')
            created_at = report.get('created_at')
        else:
            completed_at = getattr(report, 'completed_at', None)
            created_at = getattr(report, 'created_at', None)
        
        if completed_at and created_at:
            duration = completed_at - created_at
        
        # Prepare scan results summary
        scan_summary = {}
        scan_results = report.get('scan_results', []) if isinstance(report, dict) else getattr(report, 'scan_results', [])
        if scan_results:
            for scan_result in scan_results:
                tool = getattr(scan_result, 'tool', 'unknown')
                if tool not in scan_summary:
                    scan_summary[tool] = {
                        'status': getattr(scan_result, 'status', 'unknown'),
                        'findings_count': getattr(scan_result, 'findings_count', 0) or 0,
                        'duration': getattr(scan_result, 'duration', None)
                    }
        
        # Extract AI analysis insights if available
        triage_summary = None
        if isinstance(report, dict):
            statistics = report.get('statistics', {})
            if isinstance(statistics, dict):
                triage_summary = statistics.get('triage_summary')
        else:
            if hasattr(report, 'statistics') and isinstance(report.statistics, dict):
                triage_summary = report.statistics.get('triage_summary')
        
        # Extract AI insights from report
        ai_insights = None
        if isinstance(report, dict):
            ai_insights = report.get('ai_insights')
        else:
            ai_insights = getattr(report, 'ai_insights', None)
        
        print(f"REPORT GENERATOR DEBUG: AI insights found: {ai_insights is not None}")
        
        return {
            'report': report,
            'generation_time': datetime.now(),
            'statistics': {
                'total_findings': total_findings,
                'true_positives': true_positives,
                'false_positives': false_positives,
                'accuracy': (true_positives / total_findings * 100) if total_findings > 0 and true_positives is not None else 0,
                'high_priority_findings': high_priority_findings,
                'avg_confidence': avg_confidence
            },
            'findings_by_severity': findings_by_severity,
            'findings_by_tool': findings_by_tool,
            'scan_summary': scan_summary,
            'duration': duration,
            'triage_summary': triage_summary,
            'ai_insights': ai_insights,
            'severity_colors': {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745',
                'info': '#17a2b8'
            }
        }
    
    def _generate_json_report(self, report: EngagementReport, report_data: Dict[str, Any]) -> Path:
        """Generate JSON report.
        
        Args:
            report: Engagement report
            report_data: Processed report data
            
        Returns:
            Path to generated JSON file
        """
        # Handle both dictionary and object inputs for engagement_id
        if isinstance(report, dict):
            engagement_id = report.get('engagement_id', report.get('id', 'unknown'))
        else:
            engagement_id = getattr(report, 'engagement_id', getattr(report, 'id', 'unknown'))
        
        file_path = self.output_dir / f"{engagement_id}_report.json"
        
        # Convert report to dict for JSON serialization
        if isinstance(report, dict):
            report_dict = report.copy()
        else:
            report_dict = report.model_dump()
        report_dict['generation_time'] = report_data['generation_time'].isoformat()
        report_dict['statistics'] = report_data['statistics']
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        return file_path
    
    def _generate_markdown_report(self, report: EngagementReport, report_data: Dict[str, Any]) -> Path:
        """Generate Markdown report.
        
        Args:
            report: Engagement report
            report_data: Processed report data
            
        Returns:
            Path to generated Markdown file
        """
        # Handle both dictionary and object inputs for engagement_id
        if isinstance(report, dict):
            engagement_id = report.get('engagement_id', report.get('id', 'unknown'))
        else:
            engagement_id = getattr(report, 'engagement_id', getattr(report, 'id', 'unknown'))
        
        file_path = self.output_dir / f"{engagement_id}_report.md"
        
        template = self.jinja_env.get_template('report.md.j2')
        content = template.render(**report_data)
        
        file_path.write_text(content, encoding='utf-8')
        return file_path
    
    def _generate_html_report(self, report: EngagementReport, report_data: Dict[str, Any]) -> Path:
        """Generate HTML report.
        
        Args:
            report: Engagement report
            report_data: Processed report data
            
        Returns:
            Path to generated HTML file
        """
        # Handle both dictionary and object inputs for engagement_id
        if isinstance(report, dict):
            engagement_id = report.get('engagement_id', report.get('id', 'unknown'))
        else:
            engagement_id = getattr(report, 'engagement_id', getattr(report, 'id', 'unknown'))
        
        file_path = self.output_dir / f"{engagement_id}_report.html"
        
        template = self.jinja_env.get_template('report.html.j2')
        content = template.render(**report_data)
        
        file_path.write_text(content, encoding='utf-8')
        return file_path
    
    def _generate_pdf_report(self, report: EngagementReport, report_data: Dict[str, Any]) -> Path:
        """Generate PDF report.
        
        Args:
            report: Engagement report
            report_data: Processed report data
            
        Returns:
            Path to generated PDF file
        """
        if not WEASYPRINT_AVAILABLE:
            raise ImportError("weasyprint is required for PDF generation. Install with: pip install weasyprint")
            
        # Handle both dictionary and object inputs for engagement_id
        if isinstance(report, dict):
            engagement_id = report.get('engagement_id', report.get('id', 'unknown'))
        else:
            engagement_id = getattr(report, 'engagement_id', getattr(report, 'id', 'unknown'))
        
        file_path = self.output_dir / f"{engagement_id}_report.pdf"
        
        # Generate HTML first
        template = self.jinja_env.get_template('report.html.j2')
        html_content = template.render(**report_data)
        
        # Load CSS
        css_path = Path(__file__).parent / "templates" / "report.css"
        css_content = css_path.read_text() if css_path.exists() else ""
        
        # Generate PDF
        html_doc = HTML(string=html_content)
        css_doc = CSS(string=css_content) if css_content else None
        
        if css_doc:
            html_doc.write_pdf(str(file_path), stylesheets=[css_doc])
        else:
            html_doc.write_pdf(str(file_path))
        
        return file_path
    
    def _get_default_markdown_template(self) -> str:
        """Get default Markdown template content."""
        return '''
# Red Team Engagement Report

**Engagement ID:** {{ report.id }}  
**Target Scope:** {{ report.target_scope }}  
**Generated:** {{ generation_time.strftime('%Y-%m-%d %H:%M:%S') }}  
**Duration:** {{ duration if duration else 'N/A' }}  

## Executive Summary

{{ report.summary if report.summary else 'No summary provided.' }}

## Statistics

- **Total Findings:** {{ statistics.total_findings }}
- **True Positives:** {{ statistics.true_positives }}
- **False Positives:** {{ statistics.false_positives }}
- **Accuracy:** {{ "%.1f" | format(statistics.accuracy) }}%

## Findings by Severity

{% for severity, findings in findings_by_severity.items() %}
{% if findings %}
### {{ severity.upper() }} ({{ findings|length }})

{% for finding in findings %}
#### {{ finding.title }}

- **Target:** {{ finding.target }}
- **Tool:** {{ finding.tool }}
- **Status:** {{ finding.status.value }}
- **Confidence:** {{ "%.1f" | format(finding.confidence * 100) }}%

**Description:**  
{{ finding.description }}

{% if finding.ai_analysis %}
**AI Analysis:**  
{{ finding.ai_analysis }}
{% endif %}

{% if finding.references %}
**References:**
{% for ref in finding.references %}
- {{ ref }}
{% endfor %}
{% endif %}

---

{% endfor %}
{% endif %}
{% endfor %}

## Scan Results Summary

{% for tool, summary in scan_summary.items() %}
### {{ tool.upper() }}

- **Total Scans:** {{ summary.total_scans }}
- **Successful Scans:** {{ summary.successful_scans }}
- **Total Findings:** {{ summary.total_findings }}
- **Success Rate:** {{ "%.1f" | format((summary.successful_scans / summary.total_scans * 100) if summary.total_scans > 0 else 0) }}%

{% endfor %}

## Recommendations

{% if report.recommendations %}
{% for recommendation in report.recommendations %}
{{ loop.index }}. {{ recommendation }}
{% endfor %}
{% else %}
No specific recommendations provided.
{% endif %}

## Detailed Scan Results

{% for scan_result in report.scan_results %}
### {{ scan_result.tool.upper() }} - {{ scan_result.target }}

- **Status:** {{ scan_result.status }}
- **Findings:** {{ scan_result.findings_count }}
- **Timestamp:** {{ scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S') if scan_result.timestamp else 'N/A' }}

{% if scan_result.error %}
**Error:** {{ scan_result.error }}
{% endif %}

---

{% endfor %}

---

*Report generated by Red Team Automation Framework*
'''
    
    def _get_default_html_template(self) -> str:
        """Get default HTML template content."""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Team Engagement Report - {{ report.id }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .metadata {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .severity-critical { border-left: 5px solid #dc3545; }
        .severity-high { border-left: 5px solid #fd7e14; }
        .severity-medium { border-left: 5px solid #ffc107; }
        .severity-low { border-left: 5px solid #28a745; }
        .severity-info { border-left: 5px solid #17a2b8; }
        .finding {
            background: white;
            margin-bottom: 20px;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .finding-title {
            font-size: 1.3em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .finding-meta {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            font-size: 0.9em;
            color: #666;
        }
        .status-true-positive {
            background: #d4edda;
            color: #155724;
            padding: 2px 8px;
            border-radius: 4px;
        }
        .status-false-positive {
            background: #f8d7da;
            color: #721c24;
            padding: 2px 8px;
            border-radius: 4px;
        }
        .section {
            background: white;
            margin-bottom: 30px;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: #666;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Red Team Engagement Report</h1>
        <p>{{ report.target_scope }}</p>
    </div>

    <div class="metadata">
        <h2>Engagement Details</h2>
        <p><strong>Engagement ID:</strong> {{ report.id }}</p>
        <p><strong>Generated:</strong> {{ generation_time.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        <p><strong>Duration:</strong> {{ duration if duration else 'N/A' }}</p>
        <p><strong>Started:</strong> {{ report.created_at.strftime('%Y-%m-%d %H:%M:%S') if report.created_at else 'N/A' }}</p>
        <p><strong>Completed:</strong> {{ report.completed_at.strftime('%Y-%m-%d %H:%M:%S') if report.completed_at else 'N/A' }}</p>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-number">{{ statistics.total_findings }}</div>
            <div>Total Findings</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{{ statistics.true_positives }}</div>
            <div>True Positives</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{{ statistics.false_positives }}</div>
            <div>False Positives</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{{ "%.1f" | format(statistics.accuracy) }}%</div>
            <div>Accuracy</div>
        </div>
    </div>

    {% if report.summary %}
    <div class="section">
        <h2>Executive Summary</h2>
        <p>{{ report.summary }}</p>
    </div>
    {% endif %}

    <div class="section">
        <h2>Findings by Severity</h2>
        {% for severity, findings in findings_by_severity.items() %}
        {% if findings %}
        <h3>{{ severity.upper() }} ({{ findings|length }})</h3>
        {% for finding in findings %}
        <div class="finding severity-{{ severity }}">
            <div class="finding-title">{{ finding.title }}</div>
            <div class="finding-meta">
                <span><strong>Target:</strong> {{ finding.target }}</span>
                <span><strong>Tool:</strong> {{ finding.tool }}</span>
                <span><strong>Status:</strong> <span class="status-{{ finding.status.value.replace('_', '-') }}">{{ finding.status.value }}</span></span>
                <span><strong>Confidence:</strong> {{ "%.1f" | format(finding.confidence * 100) }}%</span>
            </div>
            <p><strong>Description:</strong> {{ finding.description }}</p>
            {% if finding.ai_analysis %}
            <p><strong>AI Analysis:</strong> {{ finding.ai_analysis }}</p>
            {% endif %}
            {% if finding.references %}
            <p><strong>References:</strong></p>
            <ul>
            {% for ref in finding.references %}
                <li>{{ ref }}</li>
            {% endfor %}
            </ul>
            {% endif %}
        </div>
        {% endfor %}
        {% endif %}
        {% endfor %}
    </div>

    <div class="section">
        <h2>Scan Results Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Tool</th>
                    <th>Total Scans</th>
                    <th>Successful</th>
                    <th>Findings</th>
                    <th>Success Rate</th>
                </tr>
            </thead>
            <tbody>
            {% for tool, summary in scan_summary.items() %}
                <tr>
                    <td>{{ tool.upper() }}</td>
                    <td>{{ summary.total_scans }}</td>
                    <td>{{ summary.successful_scans }}</td>
                    <td>{{ summary.total_findings }}</td>
                    <td>{{ "%.1f" | format((summary.successful_scans / summary.total_scans * 100) if summary.total_scans > 0 else 0) }}%</td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>

    {% if report.recommendations %}
    <div class="section">
        <h2>Recommendations</h2>
        <ol>
        {% for recommendation in report.recommendations %}
            <li>{{ recommendation }}</li>
        {% endfor %}
        </ol>
    </div>
    {% endif %}

    <div class="footer">
        <p>Report generated by Red Team Automation Framework</p>
    </div>
</body>
</html>
'''
    
    def _get_default_css(self) -> str:
        """Get default CSS for PDF generation."""
        return '''
@page {
    size: A4;
    margin: 2cm;
}

body {
    font-family: 'Arial', sans-serif;
    line-height: 1.6;
    color: #333;
    font-size: 12pt;
}

h1, h2, h3 {
    color: #2c3e50;
    page-break-after: avoid;
}

h1 {
    font-size: 24pt;
    text-align: center;
    margin-bottom: 30pt;
}

h2 {
    font-size: 18pt;
    border-bottom: 2pt solid #3498db;
    padding-bottom: 5pt;
    margin-top: 20pt;
}

h3 {
    font-size: 14pt;
    margin-top: 15pt;
}

.finding {
    border-left: 4pt solid #e74c3c;
    padding-left: 10pt;
    margin-bottom: 15pt;
    page-break-inside: avoid;
}

.severity-critical { border-left-color: #e74c3c; }
.severity-high { border-left-color: #f39c12; }
.severity-medium { border-left-color: #f1c40f; }
.severity-low { border-left-color: #27ae60; }
.severity-info { border-left-color: #3498db; }

table {
    width: 100%;
    border-collapse: collapse;
    margin: 10pt 0;
}

th, td {
    border: 1pt solid #bdc3c7;
    padding: 8pt;
    text-align: left;
}

th {
    background-color: #ecf0f1;
    font-weight: bold;
}

.metadata {
    background-color: #f8f9fa;
    padding: 15pt;
    border-radius: 5pt;
    margin-bottom: 20pt;
}

.footer {
    text-align: center;
    margin-top: 30pt;
    font-style: italic;
    color: #7f8c8d;
}
'''


# Convenience function
def generate_engagement_report(
    report: EngagementReport,
    output_dir: Optional[Path] = None,
    formats: list = None
) -> Dict[str, Path]:
    """Generate engagement report in multiple formats.
    
    Args:
        report: Engagement report data
        output_dir: Directory to save reports
        formats: List of formats to generate
        
    Returns:
        Dictionary mapping format to file path
    """
    generator = ReportGenerator(output_dir)
    return generator.generate_report(report, formats)