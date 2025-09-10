"""ProjectDiscovery tools integration for red team automation."""

import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import time

from config import settings
from schemas import ScanResult, Finding, ToolType, SeverityLevel, FindingStatus
from utils.logging import get_logger, steps_logger
from utils.scope_validator import ScopeValidator

logger = get_logger(__name__)


class ProjectDiscoveryTools:
    """Integration with ProjectDiscovery tools: subfinder, httpx, nuclei."""
    
    def __init__(self, scope_validator: ScopeValidator):
        self.scope_validator = scope_validator
        self.rate_limiter = RateLimiter(settings.rate_limit_requests_per_minute)
        
        # Tool paths - use from settings or system PATH
        self.subfinder_path = settings.subfinder_path or "subfinder"
        self.httpx_path = settings.httpx_path or "httpx"
        self.nuclei_path = settings.nuclei_path or "nuclei"
        
    async def run_subfinder(self, domains: List[str], output_dir: Path) -> ScanResult:
        """Run subfinder for subdomain enumeration.
        
        Args:
            domains: List of domains to enumerate subdomains for
            output_dir: Directory to store results
            
        Returns:
            ScanResult with discovered subdomains
        """
        # Input validation
        if not domains:
            raise ValueError("No domains provided for subfinder scan")
        
        steps_logger.log_step(
            "reconnaissance",
            f"Starting subfinder scan",
            "started",
            f"Domains: {len(domains)}"
        )
        
        start_time = time.time()
        
        try:
            # Validate domains are in scope
            valid_domains, invalid_domains = self.scope_validator.validate_target_list(domains)
            
            if invalid_domains:
                logger.warning("Some domains are out of scope", invalid=invalid_domains)
                
            if not valid_domains:
                raise ValueError("No valid domains in scope for subfinder scan")
                
            # Prepare output file
            output_file = output_dir / f"subfinder_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            # Build subfinder command
            cmd = [
                str(self.subfinder_path),  # Ensure path is string
                "-d", ",".join(valid_domains),
                "-o", str(output_file),
                "-silent",
                "-json"
            ]
            
            # Debug: Log command details
            logger.info(f"DEBUG: subfinder_path type: {type(self.subfinder_path)}")
            logger.info(f"DEBUG: subfinder_path value: {self.subfinder_path}")
            logger.info(f"DEBUG: output_file: {output_file}")
            logger.info(f"DEBUG: output_file exists: {output_file.parent.exists()}")
            logger.info(f"DEBUG: Full command: {cmd}")
            
            steps_logger.log_tool_execution(
                "subfinder",
                ", ".join(valid_domains),
                " ".join(cmd)
            )
            
            # Execute subfinder using subprocess.run for Windows compatibility
            logger.info(f"DEBUG: Executing command: {' '.join(cmd)}")
            logger.info(f"DEBUG: Working directory: {output_dir.parent}")
            
            import subprocess
            
            # Initialize variables
            stdout = ""
            stderr = ""
            exit_code = 1
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=str(output_dir.parent),
                    timeout=300  # 5 minute timeout
                )
                
                stdout = result.stdout or ""
                stderr = result.stderr or ""
                exit_code = result.returncode
                duration = time.time() - start_time
                
                logger.info(f"DEBUG: Process exit code: {exit_code}")
                logger.info(f"DEBUG: Stdout length: {len(stdout)}")
                logger.info(f"DEBUG: Stderr length: {len(stderr)}")
                if stderr:
                    logger.info(f"DEBUG: Stderr content: {stderr[:500]}")
                if stdout:
                    logger.info(f"DEBUG: Stdout preview: {stdout[:500]}")
                    
            except subprocess.TimeoutExpired:
                duration = time.time() - start_time
                stderr = "Subfinder timed out after 300 seconds"
                raise Exception(f"Subfinder timed out after 300 seconds")
            except Exception as e:
                duration = time.time() - start_time
                stderr = f"Subprocess execution failed: {str(e)}"
                raise Exception(f"Subprocess execution failed: {str(e)}")
            
            # Parse results
            subdomains = self._parse_subfinder_output(stdout, stderr)
            
            # Create findings
            findings = []
            for subdomain in subdomains:
                finding = Finding(
                    id=f"subfinder_{subdomain}_{int(time.time())}",
                    title=f"Subdomain discovered: {subdomain}",
                    description=f"Subdomain enumeration discovered: {subdomain}",
                    severity=SeverityLevel.INFO,
                    target=subdomain,
                    tool=ToolType.SUBFINDER,
                    raw_output=f"Discovered subdomain: {subdomain}"
                )
                findings.append(finding)
                
            scan_result = ScanResult(
                tool=ToolType.SUBFINDER,
                target=", ".join(valid_domains),
                command=" ".join(cmd),
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration=duration,
                findings=findings
            )
            
            steps_logger.log_step(
                "reconnaissance",
                f"Subfinder scan completed",
                "completed",
                f"Found {len(subdomains)} subdomains in {duration:.2f}s"
            )
            
            logger.info("Subfinder scan completed",
                       domains=len(valid_domains),
                       subdomains_found=len(subdomains),
                       duration=duration)
            
            return scan_result
            
        except Exception as e:
            duration = time.time() - start_time
            error_msg = f"Exception in run_subfinder: {type(e).__name__}: {str(e)}"
            steps_logger.log_step(
                "reconnaissance",
                f"Subfinder scan failed",
                "failed",
                f"Error: {error_msg} | Duration: {duration:.2f}s"
            )
            logger.error("Subfinder scan failed", error=error_msg, duration=duration)
            
            # Return a failed scan result instead of raising
            return ScanResult(
                tool=ToolType.SUBFINDER,
                target=", ".join(domains) if 'domains' in locals() else "unknown",
                command="failed",
                exit_code=1,
                stdout="",
                stderr=error_msg,
                duration=duration,
                findings=[]
            )
            
    def _parse_subfinder_output(self, stdout: str, stderr: str) -> List[str]:
        """Parse subfinder JSON output to extract subdomains."""
        subdomains = []
        
        # Handle None or empty stdout
        if not stdout:
            return subdomains
            
        for line in stdout.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    if 'host' in data:
                        subdomains.append(data['host'])
                except json.JSONDecodeError:
                    # Fallback to plain text parsing
                    if line.strip() and not line.startswith('['):
                        subdomains.append(line.strip())
                        
        return list(set(subdomains))  # Remove duplicates
        
    async def run_httpx(self, targets: List[str], output_dir: Path) -> ScanResult:
        """Run httpx for HTTP probing.
        
        Args:
            targets: List of targets (domains/IPs) to probe
            output_dir: Directory to store results
            
        Returns:
            ScanResult with HTTP probe results
        """
        # Input validation
        if not targets:
            raise ValueError("No targets provided for httpx scan")
        
        steps_logger.log_step(
            "reconnaissance",
            f"Starting httpx scan",
            "started",
            f"Targets: {len(targets)}"
        )
        
        start_time = time.time()
        input_file = None
        
        try:
            # Validate targets are in scope
            valid_targets, invalid_targets = self.scope_validator.validate_target_list(targets)
            
            if invalid_targets:
                logger.warning("Some targets are out of scope", invalid=invalid_targets)
                
            if not valid_targets:
                raise ValueError("No valid targets in scope for httpx scan")
                
            # Apply rate limiting
            await self.rate_limiter.acquire()
            
            # Prepare input file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for target in valid_targets:
                    f.write(f"{target}\n")
                input_file = f.name
                
            # Prepare output file
            output_file = output_dir / f"httpx_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            # Build httpx command
            cmd = [
                self.httpx_path,
                "-l", input_file,
                "-o", str(output_file),
                "-json",
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-follow-redirects",
                "-timeout", "10"
            ]
            
            steps_logger.log_tool_execution(
                "httpx",
                f"{len(valid_targets)} targets",
                " ".join(cmd)
            )
            
            # Execute httpx using subprocess.run for Windows compatibility
            import subprocess
            
            # Initialize variables
            stdout = ""
            stderr = ""
            exit_code = 1
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                stdout = result.stdout or ""
                stderr = result.stderr or ""
                exit_code = result.returncode
                duration = time.time() - start_time
                
            except subprocess.TimeoutExpired:
                duration = time.time() - start_time
                stderr = "Httpx timed out after 300 seconds"
                raise Exception(f"Httpx timed out after 300 seconds")
            except Exception as e:
                duration = time.time() - start_time
                stderr = f"Subprocess execution failed: {str(e)}"
                raise Exception(f"Subprocess execution failed: {str(e)}")
            
            # Parse results from output file
            if output_file.exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                http_results = self._parse_httpx_output(file_content, stderr)
            else:
                http_results = []
            
            # Create findings
            findings = []
            for result in http_results:
                finding = Finding(
                    id=f"httpx_{result.get('host', 'unknown')}_{int(time.time())}",
                    title=f"HTTP service discovered: {result.get('url', 'Unknown URL')}",
                    description=f"HTTP probe discovered service: {result.get('title', 'No title')} | Status: {result.get('status_code', 'Unknown')}",
                    severity=SeverityLevel.INFO,
                    target=result.get('host', 'Unknown'),
                    url=result.get('url'),
                    tool=ToolType.HTTPX,
                    raw_output=json.dumps(result, indent=2)
                )
                findings.append(finding)
                
            scan_result = ScanResult(
                tool=ToolType.HTTPX,
                target=f"{len(valid_targets)} targets",
                command=" ".join(cmd),
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration=duration,
                findings=findings
            )
            
            steps_logger.log_step(
                "reconnaissance",
                f"Httpx scan completed",
                "completed",
                f"Found {len(http_results)} HTTP services in {duration:.2f}s"
            )
            
            logger.info("Httpx scan completed",
                       targets=len(valid_targets),
                       services_found=len(http_results),
                       duration=duration)
            
            return scan_result
            
        except Exception as e:
            duration = time.time() - start_time
            steps_logger.log_step(
                "reconnaissance",
                f"Httpx scan failed",
                "failed",
                f"Error: {str(e)} | Duration: {duration:.2f}s"
            )
            logger.error("Httpx scan failed", error=str(e), duration=duration)
            raise
        finally:
            # Clean up temp file
            if input_file:
                Path(input_file).unlink(missing_ok=True)
            
    def _parse_httpx_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse httpx JSON output."""
        results = []
        
        # Handle None or empty stdout
        if not stdout:
            return results
            
        for line in stdout.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    results.append(data)
                except json.JSONDecodeError:
                    continue
                    
        return results
        
    async def run_nuclei(self, targets: List[str], output_dir: Path, 
                        templates: Optional[List[str]] = None,
                        severity_levels: Optional[List[str]] = None) -> ScanResult:
        """Run nuclei for vulnerability scanning.
        
        Args:
            targets: List of targets to scan
            output_dir: Directory to store results
            templates: Specific nuclei templates to use
            
        Returns:
            ScanResult with vulnerability findings
        """
        steps_logger.log_step(
            "scanning",
            f"Starting nuclei scan",
            "started",
            f"Targets: {len(targets)} | Templates: {templates or 'default'}"
        )
        
        start_time = time.time()
        
        # Input validation
        if not targets:
            raise ValueError("No targets provided for nuclei scan")
        
        # Validate severity levels if provided
        if severity_levels:
            valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
            invalid_severities = [s for s in severity_levels if s.lower() not in valid_severities]
            if invalid_severities:
                raise ValueError(f"Invalid severity levels: {invalid_severities}")
        
        input_file = None
        try:
            # Validate targets are in scope
            valid_targets, invalid_targets = self.scope_validator.validate_target_list(targets)
            
            if invalid_targets:
                logger.warning("Some targets are out of scope", invalid=invalid_targets)
                
            if not valid_targets:
                raise ValueError("No valid targets in scope for nuclei scan")
                
            # Apply rate limiting
            await self.rate_limiter.acquire()
            
            # Prepare input file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for target in valid_targets:
                    f.write(f"{target}\n")
                input_file = f.name
                
            # Prepare output file
            from pathlib import Path
            output_dir_path = Path(output_dir)
            output_file = output_dir_path / f"nuclei_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            # Build nuclei command
            cmd = [
                self.nuclei_path,
                "-l", input_file,
                "-o", str(output_file),
                "-jsonl",
                "-silent",
                "-rate-limit", "150",
                "-timeout", "30",
                "-retries", "3"
            ]
            
            # Add specific templates if provided
            if templates:
                cmd.extend(["-t", ",".join(templates)])
                
            # Add severity levels if provided
            if severity_levels:
                cmd.extend(["-severity", ",".join(severity_levels)])
                
            steps_logger.log_tool_execution(
                "nuclei",
                f"{len(valid_targets)} targets",
                " ".join(cmd)
            )
            
            # Execute nuclei
            stdout = ""
            stderr = ""
            exit_code = 0
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                stdout = result.stdout if result.stdout is not None else ""
                stderr = result.stderr if result.stderr is not None else ""
                exit_code = result.returncode
                
            except subprocess.TimeoutExpired:
                stderr = "Nuclei scan timed out after 300 seconds"
                exit_code = 124
            except Exception as e:
                stderr = f"Nuclei execution failed: {str(e)}"
                exit_code = 1
                
            duration = time.time() - start_time
            
            # Parse results from output file
            if output_file.exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                nuclei_results = self._parse_nuclei_output(file_content, stderr)
            else:
                nuclei_results = []
            
            # Create findings
            findings = []
            for result in nuclei_results:
                severity = self._map_nuclei_severity(result.get('info', {}).get('severity', 'info'))
                
                finding = Finding(
                    id=f"nuclei_{result.get('template-id', 'unknown')}_{int(time.time())}",
                    title=result.get('info', {}).get('name', 'Unknown vulnerability'),
                    description=result.get('info', {}).get('description', 'No description available'),
                    severity=severity,
                    target=result.get('host', 'Unknown'),
                    url=result.get('matched-at'),
                    tool=ToolType.NUCLEI,
                    raw_output=json.dumps(result, indent=2),
                    cve_id=self._extract_cve_from_nuclei(result),
                    references=result.get('info', {}).get('reference', [])
                )
                findings.append(finding)
                
            scan_result = ScanResult(
                tool=ToolType.NUCLEI,
                target=f"{len(valid_targets)} targets",
                command=" ".join(cmd),
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration=duration,
                findings=findings
            )
            
            steps_logger.log_step(
                "scanning",
                f"Nuclei scan completed",
                "completed",
                f"Found {len(nuclei_results)} vulnerabilities in {duration:.2f}s"
            )
            
            logger.info("Nuclei scan completed",
                       targets=len(valid_targets),
                       vulnerabilities_found=len(nuclei_results),
                       duration=duration)
            
            return scan_result
            
        except Exception as e:
            duration = time.time() - start_time
            steps_logger.log_step(
                "scanning",
                f"Nuclei scan failed",
                "failed",
                f"Error: {str(e)} | Duration: {duration:.2f}s"
            )
            logger.error("Nuclei scan failed", error=str(e), duration=duration)
            raise
        finally:
            # Clean up temp file
            if input_file:
                Path(input_file).unlink(missing_ok=True)
            
    def _parse_nuclei_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse nuclei JSON output."""
        results = []
        
        if not stdout:
            return results
        
        for line in stdout.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    results.append(data)
                except json.JSONDecodeError:
                    continue
                    
        return results
        
    def _map_nuclei_severity(self, nuclei_severity: str) -> SeverityLevel:
        """Map nuclei severity to our SeverityLevel enum."""
        severity_map = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO
        }
        return severity_map.get(nuclei_severity.lower(), SeverityLevel.INFO)
        
    def _extract_cve_from_nuclei(self, result: Dict[str, Any]) -> Optional[str]:
        """Extract CVE ID from nuclei result if available."""
        info = result.get('info', {})
        
        # Check classification for CVE
        classification = info.get('classification', {})
        if 'cve-id' in classification:
            return classification['cve-id']
            
        # Check references for CVE
        references = info.get('reference', [])
        for ref in references:
            if 'cve.mitre.org' in ref or 'CVE-' in ref:
                # Extract CVE ID from reference
                import re
                cve_match = re.search(r'CVE-\d{4}-\d+', ref)
                if cve_match:
                    return cve_match.group(0)
                    
        return None
    
    def parse_nuclei_output(self, output: str) -> List[Finding]:
        """Public method to parse nuclei output and return Finding objects.
        
        Args:
            output: Raw nuclei output string
            
        Returns:
            List of Finding objects
        """
        nuclei_results = self._parse_nuclei_output(output, "")
        findings = []
        
        for result in nuclei_results:
            severity = self._map_nuclei_severity(result.get('info', {}).get('severity', 'info'))
            
            finding = Finding(
                id=f"nuclei_{result.get('template-id', 'unknown')}_{int(time.time())}",
                title=result.get('info', {}).get('name', 'Unknown vulnerability'),
                description=result.get('info', {}).get('description', 'No description available'),
                severity=severity,
                target=result.get('host', 'Unknown'),
                url=result.get('matched-at'),
                tool=ToolType.NUCLEI,
                raw_output=json.dumps(result, indent=2),
                cve_id=self._extract_cve_from_nuclei(result),
                references=result.get('info', {}).get('reference', [])
            )
            findings.append(finding)
            
        return findings


class RateLimiter:
    """Simple rate limiter for tool execution."""
    
    def __init__(self, requests_per_minute: int):
        self.requests_per_minute = requests_per_minute
        self.min_interval = 60.0 / requests_per_minute
        self.last_request = 0.0
        
    async def acquire(self):
        """Acquire rate limit token."""
        now = time.time()
        time_since_last = now - self.last_request
        
        if time_since_last < self.min_interval:
            sleep_time = self.min_interval - time_since_last
            await asyncio.sleep(sleep_time)
            
        self.last_request = time.time()