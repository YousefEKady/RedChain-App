"""Burp Suite log parser for XML and JSON formats."""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import base64
import re

from bs4 import BeautifulSoup

from schemas import BurpIssue, Finding, ToolType, SeverityLevel, FindingStatus
from utils.logging import get_logger, steps_logger
from utils.scope_validator import ScopeValidator

logger = get_logger(__name__)


class BurpSuiteParser:
    """Parser for Burp Suite XML and JSON export files."""
    
    def __init__(self, scope_validator: ScopeValidator):
        self.scope_validator = scope_validator
        
    def parse_burp_file(self, file_path: Path) -> List[BurpIssue]:
        """Parse Burp Suite export file (XML or JSON).
        
        Args:
            file_path: Path to Burp Suite export file
            
        Returns:
            List of parsed BurpIssue objects
        """
        steps_logger.log_step(
            "parsing",
            f"Parsing Burp Suite file: {file_path.name}",
            "started",
            f"File size: {file_path.stat().st_size} bytes"
        )
        
        try:
            if not file_path.exists():
                raise FileNotFoundError(f"Burp file not found: {file_path}")
                
            # Determine file format based on extension
            if file_path.suffix.lower() == '.json':
                issues = self._parse_json_format(file_path)
            elif file_path.suffix.lower() in ['.xml', '.burp']:
                issues = self._parse_xml_format(file_path)
            else:
                # Try to auto-detect format
                issues = self._auto_detect_and_parse(file_path)
                
            # Filter issues by scope
            in_scope_issues = self._filter_by_scope(issues)
            
            steps_logger.log_step(
                "parsing",
                f"Burp Suite parsing completed",
                "completed",
                f"Parsed {len(issues)} issues, {len(in_scope_issues)} in scope"
            )
            
            logger.info("Burp Suite file parsed successfully",
                       file=str(file_path),
                       total_issues=len(issues),
                       in_scope_issues=len(in_scope_issues))
            
            return in_scope_issues
            
        except Exception as e:
            steps_logger.log_step(
                "parsing",
                f"Burp Suite parsing failed",
                "failed",
                f"Error: {str(e)}"
            )
            logger.error("Burp Suite parsing failed", file=str(file_path), error=str(e))
            raise
            
    def _parse_json_format(self, file_path: Path) -> List[BurpIssue]:
        """Parse Burp Suite JSON format."""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        issues = []
        
        # Handle different JSON structures
        if isinstance(data, list):
            # Direct list of issues
            for item in data:
                issue = self._parse_json_issue(item)
                if issue:
                    issues.append(issue)
        elif isinstance(data, dict):
            # Check for common Burp JSON structures
            if 'issues' in data:
                for item in data['issues']:
                    issue = self._parse_json_issue(item)
                    if issue:
                        issues.append(issue)
            elif 'scan_issues' in data:
                for item in data['scan_issues']:
                    issue = self._parse_json_issue(item)
                    if issue:
                        issues.append(issue)
            else:
                # Try to parse as single issue
                issue = self._parse_json_issue(data)
                if issue:
                    issues.append(issue)
                    
        return issues
        
    def _parse_json_issue(self, item: Dict[str, Any]) -> Optional[BurpIssue]:
        """Parse a single JSON issue."""
        try:
            # Map common JSON field names to our schema
            field_mappings = {
                'serial_number': ['serial_number', 'serialNumber', 'id'],
                'type': ['type', 'issue_type', 'issueType', 'type_index'],
                'name': ['name', 'issue_name', 'issueName', 'title'],
                'host': ['host', 'hostname', 'target', 'url'],
                'path': ['path', 'location', 'url_path'],
                'severity': ['severity', 'risk', 'impact'],
                'confidence': ['confidence', 'certainty'],
                'issue_background': ['issue_background', 'issueBackground', 'background', 'description'],
                'remediation_background': ['remediation_background', 'remediationBackground', 'remediation'],
                'issue_detail': ['issue_detail', 'issueDetail', 'detail', 'details'],
                'remediation_detail': ['remediation_detail', 'remediationDetail', 'fix']
            }
            
            parsed_data = {}
            
            for our_field, possible_fields in field_mappings.items():
                for field in possible_fields:
                    if field in item:
                        parsed_data[our_field] = item[field]
                        break
                        
            # Extract host from URL if needed
            if 'host' not in parsed_data and 'url' in item:
                from urllib.parse import urlparse
                parsed_url = urlparse(item['url'])
                parsed_data['host'] = parsed_url.netloc
                parsed_data['path'] = parsed_url.path
                
            # Handle vulnerability classifications
            classifications = []
            for field in ['cwe', 'owasp', 'classification', 'categories']:
                if field in item:
                    if isinstance(item[field], list):
                        classifications.extend(item[field])
                    else:
                        classifications.append(str(item[field]))
                        
            return BurpIssue(
                serial_number=parsed_data.get('serial_number'),
                type=parsed_data.get('type', 'Unknown'),
                name=parsed_data.get('name', 'Unknown Issue'),
                host=parsed_data.get('host', 'Unknown'),
                path=parsed_data.get('path', '/'),
                location=parsed_data.get('location'),
                severity=self._normalize_severity(parsed_data.get('severity', 'info')),
                confidence=self._normalize_confidence(parsed_data.get('confidence', 'tentative')),
                issue_background=parsed_data.get('issue_background'),
                remediation_background=parsed_data.get('remediation_background'),
                issue_detail=parsed_data.get('issue_detail'),
                remediation_detail=parsed_data.get('remediation_detail'),
                vulnerability_classifications=classifications
            )
            
        except Exception as e:
            logger.warning("Failed to parse JSON issue", error=str(e), item=item)
            return None
            
    def _parse_xml_format(self, file_path: Path) -> List[BurpIssue]:
        """Parse Burp Suite XML format with secure XML parsing."""
        try:
            # Security: Create secure XML parser to prevent XXE attacks
            parser = ET.XMLParser()
            # Disable external entity processing
            parser.parser.DefaultHandler = lambda data: None
            parser.parser.ExternalEntityRefHandler = lambda context, base, sysId, notationName: False
            
            tree = ET.parse(file_path, parser)
            root = tree.getroot()
        except ET.ParseError:
            # Try with BeautifulSoup for malformed XML
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            soup = BeautifulSoup(content, 'xml')
            return self._parse_xml_with_bs4(soup)
            
        issues = []
        
        # Handle different XML structures
        for issue_elem in root.findall('.//issue'):
            issue = self._parse_xml_issue(issue_elem)
            if issue:
                issues.append(issue)
                
        return issues
        
    def _parse_xml_issue(self, issue_elem: ET.Element) -> Optional[BurpIssue]:
        """Parse a single XML issue element."""
        try:
            def get_text(elem, tag, default=None):
                child = elem.find(tag)
                return child.text if child is not None else default
                
            def get_decoded_text(elem, tag, default=None):
                """Get text and decode if base64 encoded."""
                text = get_text(elem, tag, default)
                if text and text != default:
                    try:
                        # Try to decode base64
                        decoded = base64.b64decode(text).decode('utf-8')
                        return decoded
                    except:
                        return text
                return text
                
            # Extract vulnerability classifications
            classifications = []
            for vuln_elem in issue_elem.findall('.//vulnerabilityClassifications/vulnerabilityClassification'):
                if vuln_elem.text:
                    classifications.append(vuln_elem.text)
                    
            return BurpIssue(
                serial_number=get_text(issue_elem, 'serialNumber'),
                type=get_text(issue_elem, 'type', 'Unknown'),
                name=get_text(issue_elem, 'name', 'Unknown Issue'),
                host=get_text(issue_elem, 'host', 'Unknown'),
                path=get_text(issue_elem, 'path', '/'),
                location=get_text(issue_elem, 'location'),
                severity=self._normalize_severity(get_text(issue_elem, 'severity', 'info')),
                confidence=self._normalize_confidence(get_text(issue_elem, 'confidence', 'tentative')),
                issue_background=get_decoded_text(issue_elem, 'issueBackground'),
                remediation_background=get_decoded_text(issue_elem, 'remediationBackground'),
                issue_detail=get_decoded_text(issue_elem, 'issueDetail'),
                remediation_detail=get_decoded_text(issue_elem, 'remediationDetail'),
                vulnerability_classifications=classifications
            )
            
        except Exception as e:
            logger.warning("Failed to parse XML issue", error=str(e))
            return None
            
    def _parse_xml_with_bs4(self, soup: BeautifulSoup) -> List[BurpIssue]:
        """Parse XML using BeautifulSoup for malformed XML."""
        issues = []
        
        for issue_elem in soup.find_all('issue'):
            try:
                def get_text(tag_name, default=None):
                    elem = issue_elem.find(tag_name)
                    return elem.get_text() if elem else default
                    
                def get_decoded_text(tag_name, default=None):
                    text = get_text(tag_name, default)
                    if text and text != default:
                        try:
                            decoded = base64.b64decode(text).decode('utf-8')
                            return decoded
                        except:
                            return text
                    return text
                    
                # Extract classifications
                classifications = []
                for vuln_elem in issue_elem.find_all('vulnerabilityclassification'):
                    if vuln_elem.get_text():
                        classifications.append(vuln_elem.get_text())
                        
                issue = BurpIssue(
                    serial_number=get_text('serialnumber'),
                    type=get_text('type', 'Unknown'),
                    name=get_text('name', 'Unknown Issue'),
                    host=get_text('host', 'Unknown'),
                    path=get_text('path', '/'),
                    location=get_text('location'),
                    severity=self._normalize_severity(get_text('severity', 'info')),
                    confidence=self._normalize_confidence(get_text('confidence', 'tentative')),
                    issue_background=get_decoded_text('issuebackground'),
                    remediation_background=get_decoded_text('remediationbackground'),
                    issue_detail=get_decoded_text('issuedetail'),
                    remediation_detail=get_decoded_text('remediationdetail'),
                    vulnerability_classifications=classifications
                )
                issues.append(issue)
                
            except Exception as e:
                logger.warning("Failed to parse BS4 issue", error=str(e))
                continue
                
        return issues
        
    def _auto_detect_and_parse(self, file_path: Path) -> List[BurpIssue]:
        """Auto-detect file format and parse accordingly."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read(1024)  # Read first 1KB
            
        if content.strip().startswith('{') or content.strip().startswith('['):
            # Likely JSON
            return self._parse_json_format(file_path)
        elif content.strip().startswith('<'):
            # Likely XML
            return self._parse_xml_format(file_path)
        else:
            raise ValueError(f"Unable to determine format of file: {file_path}")
            
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity values from Burp to standard format."""
        severity = severity.lower().strip()
        
        severity_map = {
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'information': 'info',
            'info': 'info',
            'informational': 'info',
            'critical': 'critical'
        }
        
        return severity_map.get(severity, 'info')
        
    def _normalize_confidence(self, confidence: str) -> str:
        """Normalize confidence values from Burp."""
        confidence = confidence.lower().strip()
        
        confidence_map = {
            'certain': 'certain',
            'firm': 'firm',
            'tentative': 'tentative'
        }
        
        return confidence_map.get(confidence, 'tentative')
        
    def _filter_by_scope(self, issues: List[BurpIssue]) -> List[BurpIssue]:
        """Filter issues to only include those in scope."""
        in_scope_issues = []
        
        for issue in issues:
            is_valid, reason = self.scope_validator.is_target_in_scope(issue.host)
            if is_valid:
                in_scope_issues.append(issue)
                logger.debug("Issue in scope", host=issue.host, issue=issue.name)
            else:
                logger.debug("Issue out of scope", host=issue.host, reason=reason)
                
        return in_scope_issues
        
    def convert_to_findings(self, burp_issues: List[BurpIssue]) -> List[Finding]:
        """Convert BurpIssue objects to Finding objects.
        
        Args:
            burp_issues: List of BurpIssue objects
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        for issue in burp_issues:
            try:
                # Map Burp severity to our severity levels
                severity_map = {
                    'critical': SeverityLevel.CRITICAL,
                    'high': SeverityLevel.HIGH,
                    'medium': SeverityLevel.MEDIUM,
                    'low': SeverityLevel.LOW,
                    'info': SeverityLevel.INFO
                }
                
                severity = severity_map.get(issue.severity.lower(), SeverityLevel.INFO)
                
                # Build URL if possible
                url = None
                if issue.host and issue.path:
                    # Determine protocol (assume HTTPS for common ports)
                    protocol = 'https' if ':443' in issue.host or not ':' in issue.host else 'http'
                    url = f"{protocol}://{issue.host}{issue.path}"
                    
                # Extract CVE from classifications if available
                cve_id = None
                for classification in issue.vulnerability_classifications:
                    cve_match = re.search(r'CVE-\d{4}-\d+', classification)
                    if cve_match:
                        cve_id = cve_match.group(0)
                        break
                        
                # Build description
                description_parts = []
                if issue.issue_background:
                    description_parts.append(f"Background: {issue.issue_background}")
                if issue.issue_detail:
                    description_parts.append(f"Details: {issue.issue_detail}")
                    
                description = "\n\n".join(description_parts) if description_parts else issue.name
                
                # Build remediation
                remediation_parts = []
                if issue.remediation_background:
                    remediation_parts.append(f"Background: {issue.remediation_background}")
                if issue.remediation_detail:
                    remediation_parts.append(f"Details: {issue.remediation_detail}")
                    
                remediation = "\n\n".join(remediation_parts) if remediation_parts else None
                
                finding = Finding(
                    id=f"burp_{issue.serial_number or 'unknown'}_{int(datetime.now().timestamp())}",
                    title=issue.name,
                    description=description,
                    severity=severity,
                    target=issue.host,
                    url=url,
                    tool=ToolType.BURP_SUITE,
                    raw_output=self._serialize_burp_issue(issue),
                    cve_id=cve_id,
                    remediation=remediation,
                    references=issue.vulnerability_classifications,
                    confidence=self._map_confidence_to_score(issue.confidence)
                )
                
                findings.append(finding)
                
                steps_logger.log_finding_discovered(
                    finding.title,
                    finding.severity,
                    finding.target,
                    "burp_suite"
                )
                
            except Exception as e:
                logger.warning("Failed to convert Burp issue to finding", 
                             issue_name=issue.name, error=str(e))
                continue
                
        logger.info("Converted Burp issues to findings", 
                   burp_issues=len(burp_issues),
                   findings=len(findings))
        
        return findings
        
    def _serialize_burp_issue(self, issue: BurpIssue) -> str:
        """Serialize BurpIssue to JSON string for raw_output."""
        return json.dumps({
            'serial_number': issue.serial_number,
            'type': issue.type,
            'name': issue.name,
            'host': issue.host,
            'path': issue.path,
            'location': issue.location,
            'severity': issue.severity,
            'confidence': issue.confidence,
            'issue_background': issue.issue_background,
            'remediation_background': issue.remediation_background,
            'issue_detail': issue.issue_detail,
            'remediation_detail': issue.remediation_detail,
            'vulnerability_classifications': issue.vulnerability_classifications
        }, indent=2)
        
    def _map_confidence_to_score(self, confidence: str) -> float:
        """Map Burp confidence levels to numeric scores."""
        confidence_map = {
            'certain': 0.9,
            'firm': 0.7,
            'tentative': 0.4
        }
        return confidence_map.get(confidence.lower(), 0.5)