"""Main workflow orchestrator for red team automation."""

import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta

try:
    # Try relative imports first (when used as module)
    from ..schemas import (
        Scope, Finding, ScanResult, EngagementReport, 
        EngagementConfig, StepLog, FindingStatus, SeverityLevel
    )
    from ..agents.security_agent import SecurityAgent
    from ..tools.project_discovery import ProjectDiscoveryTools
    from ..tools.burp_parser import BurpSuiteParser
    from ..rag.knowledge_base import KnowledgeBase
    from ..utils.scope_validator import load_scope_from_file
    from ..utils.safety_checks import EngagementSafetyManager
    from ..utils.logging import get_logger, steps_logger
    from config import settings
    # Removed to avoid circular import - will import locally where needed
    from database.database import get_db
    from database.models import EngagementStatus
except ImportError:
    # Fall back to absolute imports (when run as script)
    from schemas import (
        Scope, Finding, ScanResult, EngagementReport, 
        EngagementConfig, StepLog, FindingStatus, SeverityLevel
    )
    from agents.security_agent import SecurityAgent
    from tools.project_discovery import ProjectDiscoveryTools
    from tools.burp_parser import BurpSuiteParser
    from rag.knowledge_base import KnowledgeBase
    from utils.scope_validator import load_scope_from_file
    from utils.safety_checks import EngagementSafetyManager
    from utils.logging import get_logger, steps_logger
    from config import settings
    from services.report_scheduler import scheduler
    from database.database import get_db
    from database.models import EngagementStatus

logger = get_logger(__name__)


class RedTeamOrchestrator:
    """Main orchestrator for red team automation workflows."""
    
    def __init__(self, config: Optional[EngagementConfig] = None):
        """Initialize the orchestrator.
        
        Args:
            config: Optional engagement configuration
        """
        # Input validation
        if config is not None and not isinstance(config, EngagementConfig):
            raise TypeError("Config must be an EngagementConfig instance or None")
            
        self.config = config
        self.scope: Optional[Scope] = None
        self.safety_manager: Optional[EngagementSafetyManager] = None
        self.progress_callback = None  # Progress callback for API updates
        
        # Initialize components with error handling
        try:
            self.security_agent = SecurityAgent()
            self.knowledge_base = KnowledgeBase(self.security_agent)
        except Exception as e:
            logger.error(f"Failed to initialize AI components: {e}")
            raise RuntimeError(f"Failed to initialize orchestrator components: {e}")
            
        self.pd_tools: Optional[ProjectDiscoveryTools] = None
        self.burp_parser: Optional[BurpSuiteParser] = None
        
        # Engagement state
        print(f"DEBUG: config = {config}")
        print(f"DEBUG: config type = {type(config)}")
        if config:
            print(f"DEBUG: hasattr(config, 'engagement_id') = {hasattr(config, 'engagement_id')}")
            if hasattr(config, 'engagement_id'):
                print(f"DEBUG: config.engagement_id = {config.engagement_id}")
        
        if config and hasattr(config, 'engagement_id'):
            self.engagement_id = config.engagement_id
            self.output_dir = config.output_dir
            print(f"DEBUG: Using config engagement_id: {self.engagement_id}, output_dir: {self.output_dir}")
            logger.info(f"Using config engagement_id: {self.engagement_id}, output_dir: {self.output_dir}")
        else:
            # Fallback to generated ID if not provided
            self.engagement_id = f"engagement_{int(datetime.now().timestamp())}"
            self.output_dir = Path(settings.OUTPUT_DIR) / self.engagement_id
            print(f"DEBUG: Using fallback engagement_id: {self.engagement_id}, output_dir: {self.output_dir}")
            logger.info(f"Using fallback engagement_id: {self.engagement_id}, output_dir: {self.output_dir}")
            
        self.findings: List[Finding] = []
        self.scan_results: List[ScanResult] = []
        self.engagement_start_time: Optional[datetime] = None
        self.engagement_end_time: Optional[datetime] = None
        
        # Initialize output directory
        try:
            print(f"DEBUG: About to create output directory: {self.output_dir}")
            print(f"DEBUG: Current working directory: {Path.cwd()}")
            print(f"DEBUG: Output directory absolute path: {self.output_dir.absolute()}")
            self.output_dir.mkdir(parents=True, exist_ok=True)
            print(f"DEBUG: Successfully created output directory: {self.output_dir}")
            print(f"DEBUG: Directory exists check: {self.output_dir.exists()}")
        except Exception as e:
            print(f"DEBUG: Failed to create output directory: {e}")
            raise
        
        logger.info("Red team orchestrator initialized", 
                   engagement_id=self.engagement_id)
        
    async def run_engagement(self, scope: Optional[Scope] = None, 
                           burp_files: Optional[List[Path]] = None,
                           dry_run: bool = False) -> EngagementReport:
        """Run a complete red team engagement.
        
        Args:
            scope: Scope object with engagement targets and configuration
            burp_files: Optional list of Burp Suite export files
            dry_run: If True, use mocked outputs for testing
            
        Returns:
            Complete engagement report
        """
        # Input validation
        if scope is not None and not isinstance(scope, Scope):
            raise TypeError("scope must be a Scope object or None")
            
        if burp_files is not None:
            if not isinstance(burp_files, list):
                raise TypeError("burp_files must be a list of Path objects or None")
            for bf in burp_files:
                if not isinstance(bf, Path):
                    raise TypeError("All items in burp_files must be Path objects")
                    
        if not isinstance(dry_run, bool):
            raise TypeError("dry_run must be a boolean")
            
        self.engagement_start_time = datetime.now()
        
        steps_logger.log_step(
            "engagement",
            f"Starting red team engagement",
            "started",
            f"ID: {self.engagement_id}, Dry run: {dry_run}"
        )
        
        try:
            # Phase 1: Setup and Safety Checks
            await self._phase_setup_and_safety(scope)
            
            # Phase 2: Reconnaissance
            await self._phase_reconnaissance(dry_run)
            
            # Phase 3: Vulnerability Scanning
            await self._phase_vulnerability_scanning(dry_run)
            
            # Phase 4: Burp Suite Integration
            if burp_files:
                await self._phase_burp_integration(burp_files)
                
            # Phase 5: Finding Triage
            await self._phase_finding_triage()
            
            # Phase 6: Knowledge Base Learning
            await self._phase_knowledge_learning()
            
            # Phase 7: Report Generation
            report = await self._phase_report_generation()
            
            self.engagement_end_time = datetime.now()
            duration = self.engagement_end_time - self.engagement_start_time
            
            steps_logger.log_step(
                "engagement",
                f"Red team engagement completed",
                "completed",
                f"Duration: {duration}, Findings: {len(self.findings)}"
            )
            
            logger.info("Engagement completed successfully", 
                       engagement_id=self.engagement_id,
                       duration_seconds=duration.total_seconds(),
                       findings_count=len(self.findings))
            
            return report
            
        except Exception as e:
            self.engagement_end_time = datetime.now()
            
            steps_logger.log_step(
                "engagement",
                f"Red team engagement failed",
                "failed",
                f"Error: {str(e)}"
            )
            
            logger.error("Engagement failed", 
                        engagement_id=self.engagement_id, error=str(e))
            raise
            
    async def _phase_setup_and_safety(self, scope: Optional[Scope]):
        """Phase 1: Setup and safety checks.
        
        Args:
            scope: Scope object with engagement configuration
        """
        # Update progress via callback if available
        if self.progress_callback:
            self.progress_callback("setup", "started", "Validating scope and safety")
            
        steps_logger.log_step(
            "setup",
            "Starting setup and safety checks",
            "started",
            "Validating scope and safety"
        )
        
        try:
            # Use provided scope or load from default file
            if scope:
                self.scope = scope
                logger.info("Using provided scope object")
            else:
                # Fallback to default scope file if no scope provided
                default_scope_file = Path(settings.SCOPE_FILE_PATH)
                if not default_scope_file.exists():
                    raise FileNotFoundError(
                        f"No scope provided and default scope file not found: {default_scope_file}. "
                        f"Please provide a scope object or create the default scope file."
                    )
                self.scope = load_scope_from_file(default_scope_file)
                logger.info("Loaded scope from default file")
                
            # Validate scope
            if not self.scope:
                raise ValueError("Failed to load scope configuration")
            if not self.scope.targets:
                raise ValueError("Scope must contain at least one target")
                
            logger.info("Scope validated", 
                       targets_count=len(self.scope.targets),
                       excluded_count=len(self.scope.excluded_targets))
            
            # Initialize safety manager
            self.safety_manager = EngagementSafetyManager(self.scope)
            
            # Skip scope file validation when using scope objects (from API)
            skip_scope_file_check = scope is not None
            if skip_scope_file_check:
                logger.info("Using scope object, skipping scope.yaml file validation")
            
            # Run pre-engagement safety checks
            checks_passed, issues = self.safety_manager.pre_engagement_checks(skip_scope_file_check)
            if not checks_passed:
                raise ValueError(f"Safety checks failed: {'; '.join(issues)}")
                
            # Authorize engagement
            if not self.safety_manager.authorize_engagement():
                raise ValueError("Engagement authorization failed")
                
            # Initialize tools with scope validation
            try:
                from ..utils.scope_validator import ScopeValidator
            except ImportError:
                from utils.scope_validator import ScopeValidator
            scope_validator = ScopeValidator(self.scope)
            
            self.pd_tools = ProjectDiscoveryTools(scope_validator)
            self.burp_parser = BurpSuiteParser(scope_validator)
            
            steps_logger.log_step(
                "setup",
                "Setup and safety checks completed",
                "completed",
                f"Authorized for {len(self.scope.targets)} targets"
            )
            
        except Exception as e:
            steps_logger.log_step(
                "setup",
                "Setup and safety checks failed",
                "failed",
                str(e)
            )
            raise
            
    async def _phase_reconnaissance(self, dry_run: bool):
        """Phase 2: Reconnaissance using subfinder.
        
        Args:
            dry_run: Whether to use mocked outputs
        """
        # Update progress via callback if available
        if self.progress_callback:
            self.progress_callback("reconnaissance", "started", "Subdomain enumeration with subfinder")
            
        steps_logger.log_step(
            "reconnaissance",
            "Starting reconnaissance phase",
            "started",
            "Subdomain enumeration with subfinder"
        )
        
        try:
            # Validate scope before processing
            if not self.scope or not self.scope.targets:
                raise ValueError("No scope or targets available for reconnaissance")
                
            # Extract domains from scope with validation
            domains = []
            for target in self.scope.targets:
                if not target or not target.target:
                    logger.warning(f"Skipping empty target in scope")
                    continue
                    
                if target.type == "domain" and not target.target.startswith('*.'):
                    # Basic domain validation
                    domain = target.target.strip().lower()
                    if domain and '.' in domain:
                        domains.append(domain)
                    else:
                        logger.warning(f"Skipping invalid domain format: {target.target}")
            
            logger.info(f"DEBUG: Extracted {len(domains)} valid domains from scope: {domains}")
            steps_logger.log_step(
                "reconnaissance",
                f"Extracted {len(domains)} valid domains from scope",
                "started",
                f"Domains: {domains}"
            )
            
            if not domains:
                logger.warning("No valid domains found in scope for reconnaissance")
                steps_logger.log_step(
                    "reconnaissance",
                    "No valid domains found in scope",
                    "warning",
                    "Skipping reconnaissance phase - ensure scope contains valid domain targets"
                )
                return
                
            # Run subfinder for each domain
            for domain in domains:
                try:
                    if dry_run:
                        # Mock subfinder results
                        subdomains = [
                            f"www.{domain}",
                            f"api.{domain}",
                            f"admin.{domain}",
                            f"test.{domain}"
                        ]
                        scan_result = ScanResult(
                            tool="subfinder",
                            target=domain,
                            status="completed",
                            output=json.dumps({"subdomains": subdomains}),
                            findings_count=len(subdomains)
                        )
                    else:
                        logger.info(f"DEBUG: About to call run_subfinder for domain: {domain}")
                        steps_logger.log_step(
                            "reconnaissance",
                            f"Calling subfinder for domain: {domain}",
                            "info",
                            f"Output dir: {self.output_dir}"
                        )
                        scan_result = await self.pd_tools.run_subfinder([domain], self.output_dir)
                        logger.info(f"DEBUG: Subfinder returned: {scan_result}")
                        steps_logger.log_step(
                            "reconnaissance",
                            f"Subfinder completed for {domain}",
                            "info",
                            f"Status: {scan_result.status}, Findings: {scan_result.findings_count}"
                        )
                        
                    self.scan_results.append(scan_result)
                    
                    logger.info("Subfinder completed", 
                               domain=domain, 
                               findings=scan_result.findings_count)
                    
                except Exception as e:
                    logger.error("Subfinder failed", domain=domain, error=str(e))
                    continue
                    
            steps_logger.log_step(
                "reconnaissance",
                "Reconnaissance phase completed",
                "completed",
                f"Scanned {len(domains)} domains"
            )
            
        except Exception as e:
            steps_logger.log_step(
                "reconnaissance",
                "Reconnaissance phase failed",
                "failed",
                str(e)
            )
            raise
            
    async def _phase_vulnerability_scanning(self, dry_run: bool):
        """Phase 3: Vulnerability scanning with httpx and nuclei.
        
        Args:
            dry_run: Whether to use mocked outputs
        """
        # Update progress via callback if available
        if self.progress_callback:
            self.progress_callback("vulnerability_scanning", "started", "HTTP probing and vulnerability detection")
            
        steps_logger.log_step(
            "vulnerability_scanning",
            "Starting vulnerability scanning phase",
            "started",
            "HTTP probing and vulnerability detection"
        )
        
        try:
            # Collect all targets (from scope + discovered subdomains)
            targets = set()
            
            # Add scope targets
            for target in self.scope.targets:
                if target.type in ["domain", "ip"]:
                    targets.add(target.target)
                    
            # Add discovered subdomains from reconnaissance
            for scan_result in self.scan_results:
                if scan_result.tool == "subfinder" and scan_result.status == "completed":
                    try:
                        output_data = json.loads(scan_result.output)
                        if "subdomains" in output_data:
                            targets.update(output_data["subdomains"])
                    except json.JSONDecodeError:
                        continue
                        
            targets = list(targets)[:50]  # Limit for safety
            
            if not targets:
                logger.warning("No targets found for vulnerability scanning")
                return
                
            # Phase 3a: HTTP probing with httpx
            live_targets = []
            for target in targets:
                try:
                    if dry_run:
                        # Mock httpx results
                        scan_result = ScanResult(
                            tool="httpx",
                            target=target,
                            status="completed",
                            output=json.dumps({
                                "url": f"https://{target}",
                                "status_code": 200,
                                "title": f"Test Site - {target}",
                                "tech": ["nginx", "php"]
                            }),
                            findings_count=1
                        )
                        live_targets.append(target)
                    else:
                        scan_result = await self.pd_tools.run_httpx([target], self.output_dir)
                        # Check if httpx found any live hosts (exit code 0 and findings)
                        if scan_result.exit_code == 0 and len(scan_result.findings) > 0:
                            # Extract actual URLs from httpx findings instead of using domain names
                            for finding in scan_result.findings:
                                if hasattr(finding, 'url') and finding.url:
                                    live_targets.append(finding.url)
                                elif hasattr(finding, 'raw_output'):
                                    try:
                                        # Parse raw_output JSON to extract URL
                                        import json
                                        raw_data = json.loads(finding.raw_output)
                                        if 'url' in raw_data:
                                            live_targets.append(raw_data['url'])
                                    except (json.JSONDecodeError, KeyError):
                                        # Fallback to original target if parsing fails
                                        live_targets.append(target)
                            
                    self.scan_results.append(scan_result)
                    
                except Exception as e:
                    logger.error("HTTPx failed", target=target, error=str(e))
                    continue
                    
            # Phase 3b: Vulnerability scanning with nuclei
            if live_targets:
                for target in live_targets[:20]:  # Limit nuclei targets
                    try:
                        if dry_run:
                            # Mock nuclei results with sample findings
                            mock_findings = [
                                {
                                    "template": "ssl-issuer",
                                    "severity": "info",
                                    "matched-at": f"https://{target}",
                                    "info": {"name": "SSL Certificate Issuer"}
                                },
                                {
                                    "template": "tech-detect",
                                    "severity": "info", 
                                    "matched-at": f"https://{target}",
                                    "info": {"name": "Technology Detection"}
                                }
                            ]
                            scan_result = ScanResult(
                                tool="nuclei",
                                target=target,
                                status="completed",
                                output=json.dumps(mock_findings),
                                findings_count=len(mock_findings)
                            )
                        else:
                            # Use default templates if none specified in config
                            templates = None
                            if self.config and hasattr(self.config, 'nuclei_templates') and self.config.nuclei_templates:
                                templates = self.config.nuclei_templates
                            else:
                                # Use NO templates to allow nuclei to use all available templates (like the successful engagement)
                                templates = None
                            
                            scan_result = await self.pd_tools.run_nuclei(
                                [target], 
                                self.output_dir, 
                                templates
                            )
                            
                        self.scan_results.append(scan_result)
                        
                        # Convert nuclei findings to Finding objects
                        # Accept findings if scan succeeded (exit_code 0) or timed out but found vulnerabilities (exit_code 124)
                        if scan_result.findings and (scan_result.exit_code == 0 or scan_result.exit_code == 124):
                            # Nuclei findings are already parsed in the scan_result.findings
                            self.findings.extend(scan_result.findings)
                            steps_logger.log_step(
                                "vulnerability_scanning",
                                f"Added {len(scan_result.findings)} findings from Nuclei",
                                "completed",
                                f"Exit code: {scan_result.exit_code}, Findings: {len(scan_result.findings)}"
                            )
                            
                    except Exception as e:
                        logger.error("Nuclei failed", target=target, error=str(e))
                        continue
                        
            steps_logger.log_step(
                "vulnerability_scanning",
                "Vulnerability scanning phase completed",
                "completed",
                f"Scanned {len(targets)} targets, found {len(self.findings)} findings"
            )
            
        except Exception as e:
            steps_logger.log_step(
                "vulnerability_scanning",
                "Vulnerability scanning phase failed",
                "failed",
                str(e)
            )
            raise
            
    async def _phase_burp_integration(self, burp_files: List[Path]):
        """Phase 4: Burp Suite integration.
        
        Args:
            burp_files: List of Burp Suite export files
        """
        steps_logger.log_step(
            "burp_integration",
            "Starting Burp Suite integration",
            "started",
            f"Processing {len(burp_files)} Burp files"
        )
        
        try:
            for burp_file in burp_files:
                try:
                    # Parse Burp file
                    burp_issues = self.burp_parser.parse_burp_file(burp_file)
                    
                    # Convert to findings
                    burp_findings = self.burp_parser.convert_to_findings(burp_issues)
                    self.findings.extend(burp_findings)
                    
                    logger.info("Burp file processed", 
                               file=str(burp_file),
                               issues=len(burp_issues),
                               findings=len(burp_findings))
                    
                except Exception as e:
                    logger.error("Burp file processing failed", 
                                file=str(burp_file), error=str(e))
                    continue
                    
            steps_logger.log_step(
                "burp_integration",
                "Burp Suite integration completed",
                "completed",
                f"Processed {len(burp_files)} files"
            )
            
        except Exception as e:
            steps_logger.log_step(
                "burp_integration",
                "Burp Suite integration failed",
                "failed",
                str(e)
            )
            raise
            
    async def _phase_finding_triage(self):
        """Phase 5: Enhanced finding triage using AI with batch analysis and prioritization."""
        # Update progress via callback if available
        if self.progress_callback:
            self.progress_callback("triage", "started", f"Triaging {len(self.findings)} findings with AI-powered analysis")
            
        steps_logger.log_step(
            "triage",
            "Starting enhanced finding triage phase",
            "started",
            f"Triaging {len(self.findings)} findings with AI-powered analysis"
        )
        
        try:
            if not self.findings:
                # Create empty triage summary for zero findings case
                triage_summary = {
                    "total_findings": 0,
                    "triaged_count": 0,
                    "high_priority_findings": 0,
                    "false_positives_detected": 0,
                    "patterns_detected": 0,
                    "batch_insights": "No findings detected during the security assessment. This could indicate either a secure target or limited scope coverage."
                }
                
                # Store triage summary for reporting
                print(f"ORCHESTRATOR DEBUG: Storing empty triage_summary: {triage_summary}")
                self.triage_summary = triage_summary
                print(f"ORCHESTRATOR DEBUG: Empty triage_summary stored, hasattr check: {hasattr(self, 'triage_summary')}")
                
                steps_logger.log_step(
                    "triage",
                    "No findings to triage",
                    "completed",
                    "Created empty triage summary for reporting"
                )
                return
            
            # Step 1: Batch analysis for pattern detection and efficiency
            logger.info("Starting batch analysis of findings")
            batch_analysis = await self.security_agent.batch_analyze_findings(self.findings)
            
            # Step 2: Prioritize findings based on AI analysis
            logger.info("Prioritizing findings based on risk assessment")
            prioritized_findings = await self.security_agent.prioritize_findings(self.findings)
            
            # Step 3: Individual triage with enhanced context
            triaged_count = 0
            high_priority_count = 0
            false_positive_count = 0
            
            for finding in prioritized_findings:
                try:
                    # Get enhanced triage context from knowledge base and batch analysis
                    context = self.knowledge_base.get_triage_context(finding)
                    
                    # Add batch analysis insights to context
                    batch_context = {
                        "batch_insights": batch_analysis.get("insights", ""),
                        "pattern_analysis": batch_analysis.get("patterns_detected", []),
                        "priority_score": finding.metadata.get("priority_score", 0.5) if hasattr(finding, 'metadata') else 0.5,
                        "potential_false_positive": finding.id in batch_analysis.get("potential_false_positives", []),
                        "high_confidence": finding.id in batch_analysis.get("high_confidence_findings", [])
                    }
                    
                    # Perform enhanced triage using security agent
                    triage_result = await self.security_agent.triage_finding(
                        finding, {**context, **batch_context}
                    )
                    
                    # Update finding with triage results
                    finding.status = triage_result["status"]
                    finding.ai_analysis = triage_result.get("reasoning", "")
                    finding.confidence = triage_result.get("confidence", 0.5)
                    finding.remediation = triage_result.get("remediation", "")
                    finding.references = triage_result.get("references", [])
                    
                    # Add batch analysis metadata
                    if not hasattr(finding, 'metadata'):
                        finding.metadata = {}
                    finding.metadata.update(batch_context)
                    
                    # Add to vector store for future reference
                    self.knowledge_base.vector_store.add_finding(finding)
                    
                    triaged_count += 1
                    
                    # Track statistics
                    if finding.status == FindingStatus.TRUE_POSITIVE and batch_context["priority_score"] > 0.7:
                        high_priority_count += 1
                    elif finding.status == FindingStatus.FALSE_POSITIVE:
                        false_positive_count += 1
                    
                    steps_logger.log_finding_triaged(
                        finding.title,
                        finding.status,
                        finding.confidence
                    )
                    
                except Exception as e:
                    logger.error("Finding triage failed", 
                                finding_id=finding.id, error=str(e))
                    continue
            
            # Step 4: Generate triage summary with insights
            triage_summary = {
                "total_findings": len(self.findings),
                "triaged_count": triaged_count,
                "high_priority_findings": high_priority_count,
                "false_positives_detected": false_positive_count,
                "patterns_detected": len(batch_analysis.get("patterns_detected", [])),
                "batch_insights": batch_analysis.get("insights", "")
            }
            
            # Store triage summary for reporting
            print(f"ORCHESTRATOR DEBUG: Storing triage_summary: {triage_summary}")
            self.triage_summary = triage_summary
            print(f"ORCHESTRATOR DEBUG: triage_summary stored, hasattr check: {hasattr(self, 'triage_summary')}")
            print(f"ORCHESTRATOR DEBUG: self.triage_summary content: {getattr(self, 'triage_summary', 'NOT_FOUND')}")
            
            steps_logger.log_step(
                "triage",
                "Enhanced finding triage phase completed",
                "completed",
                f"Triaged {triaged_count}/{len(self.findings)} findings. "
                f"High priority: {high_priority_count}, False positives: {false_positive_count}, "
                f"Patterns detected: {len(batch_analysis.get('patterns_detected', []))}"
            )
            
            logger.info("Enhanced triage completed",
                       total_findings=len(self.findings),
                       triaged=triaged_count,
                       high_priority=high_priority_count,
                       false_positives=false_positive_count)
            
        except Exception as e:
            steps_logger.log_step(
                "triage",
                "Enhanced finding triage phase failed",
                "failed",
                str(e)
            )
            logger.error("Enhanced triage failed", error=str(e))
            raise
            
    async def _phase_knowledge_learning(self):
        """Phase 6: Knowledge base learning."""
        steps_logger.log_step(
            "learning",
            "Starting knowledge learning phase",
            "started",
            "Extracting insights and updating knowledge base"
        )
        
        try:
            # Create engagement report for learning
            temp_report = EngagementReport(
                engagement_id=self.engagement_id,
                scope=self.scope,
                executive_summary=self._generate_engagement_summary(),
                methodology="Automated security assessment using AI-powered analysis and industry-standard tools including Subfinder, HTTPx, and Nuclei for comprehensive vulnerability discovery.",
                findings=self.findings,
                recommendations=self._generate_recommendations()
            )
            
            # Store engagement insights
            insight_id = await self.knowledge_base.store_engagement_insights(temp_report)
            
            logger.info("Engagement insights stored", insight_id=insight_id)
            
            steps_logger.log_step(
                "learning",
                "Knowledge learning phase completed",
                "completed",
                f"Stored insights: {insight_id}"
            )
            
        except Exception as e:
            steps_logger.log_step(
                "learning",
                "Knowledge learning phase failed",
                "failed",
                str(e)
            )
            # Don't raise - learning failure shouldn't stop engagement
            logger.error("Knowledge learning failed", error=str(e))
            
    async def _phase_report_generation(self) -> EngagementReport:
        """Phase 7: Report generation.
        
        Returns:
            Complete engagement report
        """
        # Update progress via callback if available
        if self.progress_callback:
            self.progress_callback("reporting", "started", "Generating final engagement report")
            
        steps_logger.log_step(
            "reporting",
            "Starting report generation phase",
            "started",
            "Generating final engagement report"
        )
        
        try:
            # Prepare AI insights if available
            ai_insights = None
            print(f"ORCHESTRATOR DEBUG: hasattr(self, 'triage_summary'): {hasattr(self, 'triage_summary')}")
            if hasattr(self, 'triage_summary'):
                print(f"ORCHESTRATOR DEBUG: self.triage_summary: {self.triage_summary}")
            
            if hasattr(self, 'triage_summary') and self.triage_summary:
                ai_insights = {
                    "analysis_generated": True,
                    "risk_assessment": f"Analyzed {self.triage_summary.get('total_findings', 0)} findings with {self.triage_summary.get('patterns_detected', 0)} patterns detected.",
                    "findings_analyzed": self.triage_summary.get('triaged_count', 0),
                    "key_concerns": [
                        f"High priority findings: {self.triage_summary.get('high_priority_findings', 0)}", 
                        f"False positives detected: {self.triage_summary.get('false_positives_detected', 0)}"
                    ],
                    "recommendations": [
                        "Review high priority findings first", 
                        "Validate AI-detected false positives", 
                        "Consider pattern-based security improvements"
                    ],
                    "full_analysis": self.triage_summary.get('batch_insights', 'AI analysis completed successfully.')
                }
                print(f"ORCHESTRATOR DEBUG: Created AI insights: {ai_insights}")
                logger.info("Including AI insights in engagement report", 
                           engagement_id=self.engagement_id,
                           insights_available=True)
            else:
                print(f"ORCHESTRATOR DEBUG: No triage_summary available, AI insights will be None")
            
            # Create final engagement report
            report = EngagementReport(
                engagement_id=self.engagement_id,
                scope=self.scope,
                executive_summary=self._generate_engagement_summary(),
                methodology="Automated security assessment using AI-powered analysis and industry-standard tools including Subfinder, HTTPx, and Nuclei for comprehensive vulnerability discovery.",
                findings=self.findings,
                recommendations=self._generate_recommendations(),
                ai_insights=ai_insights
            )
            
            steps_logger.log_step(
                "reporting",
                "Report generation phase completed",
                "completed",
                f"Report ID: {report.engagement_id}, AI insights: {ai_insights is not None}"
            )
            
            return report
            
        except Exception as e:
            steps_logger.log_step(
                "reporting",
                "Report generation phase failed",
                "failed",
                str(e)
            )
            raise
            
    def _generate_engagement_summary(self) -> str:
        """Generate enhanced engagement summary with AI analysis insights.
        
        Returns:
            Enhanced summary text with AI insights
        """
        total_findings = len(self.findings)
        true_positives = len([f for f in self.findings if f.status == FindingStatus.TRUE_POSITIVE])
        false_positives = len([f for f in self.findings if f.status == FindingStatus.FALSE_POSITIVE])
        
        # Calculate high priority findings
        high_priority_findings = len([
            f for f in self.findings 
            if (hasattr(f, 'metadata') and 
                f.metadata.get('priority_score', 0) > 0.7 and 
                f.status == FindingStatus.TRUE_POSITIVE)
        ])
        
        severity_counts = {}
        for severity in SeverityLevel:
            severity_counts[severity] = len([
                f for f in self.findings if f.severity == severity
            ])
            
        duration = (
            self.engagement_end_time - self.engagement_start_time
            if self.engagement_end_time and self.engagement_start_time
            else timedelta(0)
        )
        
        # Get triage summary if available
        triage_info = ""
        if hasattr(self, 'triage_summary'):
            triage_info = f"""
        
        AI-Powered Analysis Results:
        - Patterns Detected: {self.triage_summary.get('patterns_detected', 0)}
        - High Priority Findings: {self.triage_summary.get('high_priority_findings', 0)}
        - AI-Detected False Positives: {self.triage_summary.get('false_positives_detected', 0)}
        - Analysis Accuracy: {f'{(self.triage_summary.get("triaged_count", 0) / total_findings * 100):.1f}%' if total_findings > 0 else 'N/A (no findings)'}
        
        Key Insights:
        {self.triage_summary.get('batch_insights', 'No specific insights generated.')[:500]}...
        """
        
        # Calculate confidence metrics
        avg_confidence = 0.0
        if self.findings:
            confidences = [f.confidence for f in self.findings if f.confidence is not None]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        
        return f"""
        Red Team Engagement Summary - AI-Enhanced Analysis
        
        Scope: {self.scope.description}
        Duration: {duration}
        
        Findings Overview:
        - Total Findings: {total_findings}
        - True Positives: {true_positives}
        - False Positives: {false_positives}
        - High Priority (AI-Scored): {high_priority_findings}
        - Average Confidence: {avg_confidence:.2f}
        
        Severity Breakdown:
        - Critical: {severity_counts.get(SeverityLevel.CRITICAL, 0)}
        - High: {severity_counts.get(SeverityLevel.HIGH, 0)}
        - Medium: {severity_counts.get(SeverityLevel.MEDIUM, 0)}
        - Low: {severity_counts.get(SeverityLevel.LOW, 0)}
        - Info: {severity_counts.get(SeverityLevel.INFO, 0)}
        
        Tools Used: {', '.join(set(sr.tool for sr in self.scan_results))}
        {triage_info}
        """
        
    def _trigger_automatic_report_generation(self, engagement_id: str):
        """Trigger automatic report generation if enabled."""
        from services.report_scheduler import scheduler
        
        try:
            if not settings.auto_generate_reports or not settings.auto_report_on_completion:
                logger.debug("Automatic report generation disabled")
                return
                
            # Update database to mark engagement as completed
            with get_db() as db:
                db.execute(
                    "UPDATE engagements SET status = ?, completed_at = ? WHERE id = ?",
                    (EngagementStatus.COMPLETED.value, datetime.now().isoformat(), engagement_id)
                )
                db.commit()
                
            # Start the scheduler if not already running
            if not scheduler.running:
                scheduler.start()
                
            logger.info(f"Triggered automatic report generation for engagement {engagement_id}")
            
        except Exception as e:
            logger.error(f"Failed to trigger automatic report generation: {e}")
            
    def get_engagement_report_data(self, engagement_id: str) -> EngagementReport:
        """Get engagement report data for report generation."""
        try:
            # This method should return the engagement report data
            # For now, we'll use the current engagement data
            return self._phase_report_generation()
            
        except Exception as e:
            logger.error(f"Failed to get engagement report data: {e}")
            raise
        
    def _generate_recommendations(self) -> List[str]:
        """Generate AI-enhanced recommendations based on findings and analysis.
        
        Returns:
            List of prioritized recommendations with AI insights
        """
        recommendations = []
        
        # Count findings by severity and priority
        critical_count = len([f for f in self.findings 
                            if f.severity == SeverityLevel.CRITICAL and 
                            f.status == FindingStatus.TRUE_POSITIVE])
        high_count = len([f for f in self.findings 
                        if f.severity == SeverityLevel.HIGH and 
                        f.status == FindingStatus.TRUE_POSITIVE])
        
        # Count high priority findings from AI analysis
        high_priority_count = len([
            f for f in self.findings 
            if (hasattr(f, 'metadata') and 
                f.metadata.get('priority_score', 0) > 0.7 and 
                f.status == FindingStatus.TRUE_POSITIVE)
        ])
        
        # Count false positives detected by AI
        ai_false_positives = len([
            f for f in self.findings 
            if (hasattr(f, 'metadata') and 
                f.metadata.get('potential_false_positive', False))
        ])
        
        # Priority-based recommendations
        if critical_count > 0:
            recommendations.append(
                f"🚨 CRITICAL: Immediately address {critical_count} critical severity findings"
            )
            
        if high_priority_count > 0:
            recommendations.append(
                f"⚡ HIGH PRIORITY: Focus on {high_priority_count} AI-identified high-risk findings first"
            )
            
        if high_count > 0:
            recommendations.append(
                f"🔴 Prioritize remediation of {high_count} high severity findings"
            )
        
        # AI-specific recommendations
        if hasattr(self, 'triage_summary'):
            patterns_count = self.triage_summary.get('patterns_detected', 0)
            if patterns_count > 0:
                recommendations.append(
                    f"🔍 PATTERN ANALYSIS: {patterns_count} attack patterns detected - review for systematic vulnerabilities"
                )
            
            if ai_false_positives > 0:
                recommendations.append(
                    f"🎯 TOOL TUNING: {ai_false_positives} potential false positives identified - consider refining scan configurations"
                )
        
        # Tool effectiveness recommendations
        tool_counts = {}
        for scan_result in self.scan_results:
            tool_counts[scan_result.tool] = tool_counts.get(scan_result.tool, 0) + 1
        
        if 'nuclei' in tool_counts and tool_counts['nuclei'] > 0:
            nuclei_findings = len([f for f in self.findings if 'nuclei' in f.tool.lower()])
            if nuclei_findings == 0:
                recommendations.append(
                    "🔧 Consider expanding Nuclei template coverage for better vulnerability detection"
                )
        
        # Security posture recommendations based on findings
        finding_types = set()
        for finding in self.findings:
            if finding.status == FindingStatus.TRUE_POSITIVE:
                finding_types.add(finding.tool.lower())
        
        if 'xss' in finding_types or 'cross-site scripting' in str(finding_types).lower():
            recommendations.append(
                "🛡️ Implement Content Security Policy (CSP) to mitigate XSS vulnerabilities"
            )
        
        if 'sql' in str(finding_types).lower():
            recommendations.append(
                "💾 Review database access controls and implement parameterized queries"
            )
        
        if 'authentication' in str(finding_types).lower():
            recommendations.append(
                "🔐 Strengthen authentication mechanisms and implement multi-factor authentication"
            )
        
        # Generic but important recommendations
        recommendations.extend([
            "📊 Implement continuous security monitoring and alerting",
            "🔄 Establish regular vulnerability scanning schedule",
            "🏆 Consider implementing a bug bounty program",
            "🎓 Conduct security awareness training for development teams",
            "📋 Review and update security policies and procedures",
            "🔍 Perform regular penetration testing and security assessments"
        ])
        
        # Add AI-specific recommendations
        if hasattr(self, 'triage_summary') and self.triage_summary.get('batch_insights'):
            recommendations.append(
                "🤖 AI INSIGHT: Review the detailed AI analysis for specific remediation guidance"
            )
        
        return recommendations


# Global orchestrator instance
_orchestrator: Optional[RedTeamOrchestrator] = None


def get_orchestrator(config: Optional[EngagementConfig] = None) -> RedTeamOrchestrator:
    """Get the global orchestrator instance.
    
    Args:
        config: Optional engagement configuration
        
    Returns:
        RedTeamOrchestrator instance
    """
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = RedTeamOrchestrator(config)
    return _orchestrator


def reset_orchestrator():
    """Reset the global orchestrator instance (for testing)."""
    global _orchestrator
    _orchestrator = None