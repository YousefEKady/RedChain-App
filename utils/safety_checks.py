"""Safety checks and validation system for red team automation."""

import re
import ipaddress
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union
from urllib.parse import urlparse

from schemas import Scope, ScopeTarget
from utils.logging import get_logger, steps_logger
from config import settings

logger = get_logger(__name__)


class SafetyValidator:
    """Comprehensive safety validation for red team operations."""
    
    def __init__(self, scope: Optional[Scope] = None):
        """Initialize safety validator.
        
        Args:
            scope: Optional scope configuration
        """
        self.scope = scope
        self._dangerous_patterns = self._load_dangerous_patterns()
        
        logger.info("Safety validator initialized", 
                   has_scope=scope is not None)
        
    def validate_scope_file_exists(self) -> Tuple[bool, str]:
        """Validate that scope.yaml file exists and is readable.
        
        Returns:
            Tuple of (is_valid, reason)
        """
        scope_file = Path(settings.SCOPE_FILE_PATH)
        
        if not scope_file.exists():
            return False, f"Scope file not found: {scope_file}"
            
        if not scope_file.is_file():
            return False, f"Scope path is not a file: {scope_file}"
            
        try:
            with open(scope_file, 'r') as f:
                content = f.read()
                if not content.strip():
                    return False, "Scope file is empty"
        except Exception as e:
            return False, f"Cannot read scope file: {str(e)}"
            
        return True, "Scope file exists and is readable"
        
    def validate_target_safety(self, target: str) -> Tuple[bool, str]:
        """Validate that a target is safe to test.
        
        Args:
            target: Target to validate (domain, IP, URL)
            
        Returns:
            Tuple of (is_safe, reason)
        """
        # Input validation
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty string"
        
        target = target.strip()
        if not target:
            return False, "Target cannot be empty or whitespace only"
        
        try:
            # Check if target is in scope
            if self.scope:
                is_in_scope, scope_reason = self._is_target_in_scope(target)
                if not is_in_scope:
                    return False, f"Target out of scope: {scope_reason}"
            else:
                return False, "No scope configuration loaded"
                
            # Check for dangerous patterns
            is_safe, safety_reason = self._check_dangerous_patterns(target)
            if not is_safe:
                return False, f"Dangerous target detected: {safety_reason}"
                
            # Check for internal/private networks
            is_external, network_reason = self._check_network_safety(target)
            if not is_external:
                return False, f"Internal network detected: {network_reason}"
                
            # Check for government/military domains
            is_allowed, domain_reason = self._check_domain_restrictions(target)
            if not is_allowed:
                return False, f"Restricted domain: {domain_reason}"
                
            return True, "Target is safe to test"
            
        except Exception as e:
            logger.error("Target safety validation failed", target=target, error=str(e))
            return False, f"Validation error: {str(e)}"
            
    def validate_command_safety(self, command: str, tool_name: str = None) -> Tuple[bool, str]:
        """Validate that a command is safe to execute.
        
        Args:
            command: Command to validate
            tool_name: Name of the tool executing the command
            
        Returns:
            Tuple of (is_safe, reason)
        """
        # Input validation
        if not command or not isinstance(command, str):
            return False, "Command must be a non-empty string"
        
        command = command.strip()
        if not command:
            return False, "Command cannot be empty or whitespace only"
        
        if tool_name is not None and not isinstance(tool_name, str):
            return False, "Tool name must be a string if provided"
        
        try:
            # Check for dangerous command patterns
            dangerous_commands = [
                r'rm\s+-rf',  # Destructive file operations
                r'dd\s+if=',  # Disk operations
                r'mkfs\.',    # Format filesystem
                r'fdisk',     # Disk partitioning
                r'shutdown',  # System shutdown
                r'reboot',    # System reboot
                r'halt',      # System halt
                r'init\s+0',  # System shutdown
                r'kill\s+-9\s+1',  # Kill init process
                r':(){ :|:& };:',  # Fork bomb
                r'curl.*\|.*sh',  # Pipe to shell
                r'wget.*\|.*sh',  # Pipe to shell
                r'nc\s+.*-e',     # Netcat with execute
                r'bash\s+-i',     # Interactive bash
                r'/bin/sh\s+-i',  # Interactive shell
            ]
            
            for pattern in dangerous_commands:
                if re.search(pattern, command, re.IGNORECASE):
                    return False, f"Dangerous command pattern detected: {pattern}"
                    
            # Check for exploit-related patterns
            exploit_patterns = [
                r'msfvenom',      # Metasploit payload generation
                r'msfconsole',    # Metasploit console
                r'exploit/',      # Exploit modules
                r'payload/',      # Payload modules
                r'reverse_tcp',   # Reverse shell
                r'bind_tcp',      # Bind shell
                r'shell_',        # Shell payloads
                r'meterpreter',   # Meterpreter
            ]
            
            for pattern in exploit_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    return False, f"Exploit generation detected: {pattern}"
                    
            # Validate tool-specific commands
            if tool_name and tool_name.lower() in ['subfinder', 'httpx', 'nuclei']:
                # These are scanning tools, generally safe
                return True, "Scanning tool command is safe"
            elif tool_name and tool_name.lower() == 'burp':
                # Burp Suite operations should be safe
                return True, "Burp Suite operation is safe"
            elif tool_name:
                # Unknown tool, be cautious
                return False, f"Unknown tool: {tool_name}"
            else:
                # No tool name provided, allow but log
                return True, "Command validated without tool context"
                
        except Exception as e:
            logger.error("Command safety validation failed", 
                        command=command, tool=tool, error=str(e))
            return False, f"Validation error: {str(e)}"
            
    def validate_rate_limits(self, tool: str, target_count: int) -> Tuple[bool, str]:
        """Validate that operation respects rate limits.
        
        Args:
            tool: Tool being used
            target_count: Number of targets
            
        Returns:
            Tuple of (is_within_limits, reason)
        """
        try:
            # Define rate limits per tool
            rate_limits = {
                'subfinder': {'max_targets': 100, 'delay_seconds': 1},
                'httpx': {'max_targets': 1000, 'delay_seconds': 0.1},
                'nuclei': {'max_targets': 50, 'delay_seconds': 2},
                'burp': {'max_targets': 10, 'delay_seconds': 5}
            }
            
            tool_lower = tool.lower()
            if tool_lower not in rate_limits:
                return False, f"No rate limits defined for tool: {tool}"
                
            limits = rate_limits[tool_lower]
            
            if target_count > limits['max_targets']:
                return False, (f"Too many targets for {tool}: {target_count} > "
                             f"{limits['max_targets']}")
                             
            return True, f"Rate limits OK for {tool}"
            
        except Exception as e:
            logger.error("Rate limit validation failed", 
                        tool=tool, target_count=target_count, error=str(e))
            return False, f"Validation error: {str(e)}"
            
    def validate_engagement_config(self, config: dict) -> Tuple[bool, str]:
        """Validate engagement configuration for safety compliance.
        
        Args:
            config: Engagement configuration dictionary
            
        Returns:
            Tuple of (is_safe, reason)
        """
        # Input validation
        if not config or not isinstance(config, dict):
            return False, "Configuration must be a non-empty dictionary"
        
        try:
            # Check required safety fields
            required_fields = ['scope_file', 'authorized', 'contact_info']
            for field in required_fields:
                if field not in config:
                    return False, f"Missing required safety field: {field}"
                    
            # Validate authorization
            if not config.get('authorized', False):
                return False, "Engagement not marked as authorized"
                
            # Check for contact information
            contact_info = config.get('contact_info', '')
            if not contact_info or len(contact_info.strip()) < 10:
                return False, "Insufficient contact information provided"
                
            # Validate scope file reference
            scope_file = config.get('scope_file', '')
            if not scope_file:
                return False, "No scope file specified"
                
            # Check for explicit consent
            if not config.get('explicit_consent', False):
                return False, "Explicit consent not provided"
                
            return True, "Engagement configuration is safe"
            
        except Exception as e:
            logger.error("Engagement config validation failed", error=str(e))
            return False, f"Validation error: {str(e)}"
            
    def log_safety_check(self, check_type: str, target: str, 
                        result: bool, reason: str):
        """Log safety check results.
        
        Args:
            check_type: Type of safety check
            target: Target being checked
            result: Check result
            reason: Reason for the result
        """
        steps_logger.log_step(
            "safety_check",
            f"{check_type} check for {target}",
            "completed" if result else "failed",
            reason
        )
        
        if result:
            logger.info("Safety check passed", 
                       check_type=check_type, target=target, reason=reason)
        else:
            logger.warning("Safety check failed", 
                          check_type=check_type, target=target, reason=reason)
            
    def _is_target_in_scope(self, target: str) -> Tuple[bool, str]:
        """Check if target is within defined scope.
        
        Args:
            target: Target to check
            
        Returns:
            Tuple of (is_in_scope, reason)
        """
        if not self.scope:
            return False, "No scope defined"
            
        # Parse target to extract domain/IP
        parsed_target = self._parse_target(target)
        if not parsed_target:
            return False, "Invalid target format"
            
        # Check against included targets
        for scope_target in self.scope.targets:
            if self._target_matches_scope(parsed_target, scope_target):
                # Check if excluded (excluded_targets are strings, not ScopeTarget objects)
                for excluded_target in self.scope.excluded_targets:
                    if parsed_target == excluded_target or target == excluded_target:
                        return False, f"Target excluded: {excluded_target}"
                return True, f"Target in scope: {scope_target.target}"
                
        return False, "Target not in included scope"
        
    def _parse_target(self, target: str) -> Optional[str]:
        """Parse target to extract domain or IP.
        
        Args:
            target: Target string
            
        Returns:
            Parsed target or None if invalid
        """
        try:
            # If it looks like a URL, parse it
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                return parsed.netloc.split(':')[0]  # Remove port
            
            # If it contains a port, remove it
            if ':' in target and not target.count(':') > 1:  # Not IPv6
                target = target.split(':')[0]
                
            # Validate as IP or domain
            try:
                ipaddress.ip_address(target)
                return target  # Valid IP
            except ValueError:
                # Check if valid domain (including wildcards)
                if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
                    return target
                # Check if valid wildcard domain
                elif re.match(r'^\*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
                    return target
                    
            return None
            
        except Exception:
            return None
            
    def _target_matches_scope(self, target: str, scope_target: ScopeTarget) -> bool:
        """Check if target matches a scope target.
        
        Args:
            target: Parsed target
            scope_target: Scope target to match against
            
        Returns:
            True if target matches scope
        """
        scope_value = scope_target.target
        
        if scope_target.type == "domain":
            # Handle wildcard domains
            if scope_value.startswith('*.'):
                domain_suffix = scope_value[2:]
                return target.endswith(domain_suffix) or target == domain_suffix
            else:
                return target == scope_value
                
        elif scope_target.type == "ip":
            return target == scope_value
            
        elif scope_target.type == "cidr":
            try:
                network = ipaddress.ip_network(scope_value, strict=False)
                target_ip = ipaddress.ip_address(target)
                return target_ip in network
            except ValueError:
                return False
                
        return False
        
    def _check_dangerous_patterns(self, target: str) -> Tuple[bool, str]:
        """Check for dangerous target patterns.
        
        Args:
            target: Target to check
            
        Returns:
            Tuple of (is_safe, reason)
        """
        for pattern, description in self._dangerous_patterns.items():
            if re.search(pattern, target, re.IGNORECASE):
                return False, f"{description}: {pattern}"
                
        return True, "No dangerous patterns detected"
        
    def _check_network_safety(self, target: str) -> Tuple[bool, str]:
        """Check if target is in a safe network range.
        
        Args:
            target: Target to check
            
        Returns:
            Tuple of (is_external, reason)
        """
        try:
            # Try to parse as IP
            ip = ipaddress.ip_address(target)
            
            # Check for private networks
            if ip.is_private:
                return False, "Private network address"
            if ip.is_loopback:
                return False, "Loopback address"
            if ip.is_link_local:
                return False, "Link-local address"
            if ip.is_multicast:
                return False, "Multicast address"
                
            return True, "Public IP address"
            
        except ValueError:
            # Not an IP, assume it's a domain (already validated)
            return True, "Domain name"
            
    def _check_domain_restrictions(self, target: str) -> Tuple[bool, str]:
        """Check for restricted domain patterns.
        
        Args:
            target: Target to check
            
        Returns:
            Tuple of (is_allowed, reason)
        """
        restricted_patterns = [
            r'\.gov$',      # Government domains
            r'\.mil$',      # Military domains
            r'\.edu$',      # Educational (be cautious)
            r'localhost',   # Localhost
            r'127\.0\.0\.1', # Loopback
        ]
        
        for pattern in restricted_patterns:
            if re.search(pattern, target, re.IGNORECASE):
                return False, f"Restricted domain pattern: {pattern}"
                
        return True, "Domain is allowed"
        
    def _load_dangerous_patterns(self) -> Dict[str, str]:
        """Load dangerous target patterns.
        
        Returns:
            Dictionary of pattern -> description
        """
        return {
            r'\b(rm|del|delete)\b': "Destructive operation keywords",
            r'\b(format|fdisk|mkfs)\b': "Disk formatting keywords",
            r'\b(exploit|payload|shell)\b': "Exploit-related keywords",
            r'\b(password|passwd|shadow)\b': "Password-related keywords",
            r'[;&|`$()]': "Command injection characters",
            r'\.\.[\/\\]': "Directory traversal patterns",
            r'<script': "Script injection patterns",
            r'javascript:': "JavaScript protocol",
            r'data:': "Data protocol",
        }


class EngagementSafetyManager:
    """Manager for engagement-level safety controls."""
    
    def __init__(self, scope: Scope):
        """Initialize engagement safety manager.
        
        Args:
            scope: Engagement scope
        """
        self.scope = scope
        self.safety_validator = SafetyValidator(scope)
        self._engagement_started = False
        self._safety_checks_passed = False
        
        logger.info("Engagement safety manager initialized")
        
    def pre_engagement_checks(self, skip_scope_file_check: bool = False) -> Tuple[bool, List[str]]:
        """Perform pre-engagement safety checks.
        
        Args:
            skip_scope_file_check: If True, skip the scope.yaml file existence check
            
        Returns:
            Tuple of (all_passed, list_of_issues)
        """
        issues = []
        
        steps_logger.log_step(
            "safety_check",
            "Starting pre-engagement safety checks",
            "started",
            f"Scope: {len(self.scope.targets)} targets"
        )
        
        try:
            # Check scope file exists (only if not using temporary scope)
            if not skip_scope_file_check:
                scope_valid, scope_reason = self.safety_validator.validate_scope_file_exists()
                if not scope_valid:
                    issues.append(f"Scope validation failed: {scope_reason}")
                
            # Validate all targets in scope
            for target in self.scope.targets:
                target_safe, target_reason = self.safety_validator.validate_target_safety(
                    target.target
                )
                if not target_safe:
                    issues.append(f"Target safety failed for {target.target}: {target_reason}")
                    
            # Check for minimum required information
            if not self.scope.description:
                issues.append("Scope description is required")
                
            if len(self.scope.targets) == 0:
                issues.append("No targets defined in scope")
                
            # Log results
            if not issues:
                self._safety_checks_passed = True
                steps_logger.log_step(
                    "safety_check",
                    "Pre-engagement safety checks completed",
                    "completed",
                    "All checks passed"
                )
                logger.info("Pre-engagement safety checks passed")
            else:
                steps_logger.log_step(
                    "safety_check",
                    "Pre-engagement safety checks failed",
                    "failed",
                    f"{len(issues)} issues found"
                )
                logger.error("Pre-engagement safety checks failed", 
                           issues_count=len(issues))
                
            return len(issues) == 0, issues
            
        except Exception as e:
            error_msg = f"Safety check error: {str(e)}"
            issues.append(error_msg)
            logger.error("Pre-engagement safety check failed", error=str(e))
            return False, issues
            
    def authorize_engagement(self) -> bool:
        """Authorize engagement to start.
        
        Returns:
            True if engagement is authorized
        """
        if not self._safety_checks_passed:
            logger.error("Cannot authorize engagement: safety checks not passed")
            return False
            
        self._engagement_started = True
        
        steps_logger.log_step(
            "engagement",
            "Engagement authorized and started",
            "started",
            f"Scope: {self.scope.description}"
        )
        
        logger.info("Engagement authorized", scope_description=self.scope.description)
        return True
        
    def is_engagement_authorized(self) -> bool:
        """Check if engagement is currently authorized.
        
        Returns:
            True if engagement is authorized
        """
        return self._engagement_started and self._safety_checks_passed
        
    def emergency_stop(self, reason: str):
        """Emergency stop of engagement.
        
        Args:
            reason: Reason for emergency stop
        """
        self._engagement_started = False
        
        steps_logger.log_step(
            "engagement",
            "Emergency stop triggered",
            "stopped",
            f"Reason: {reason}"
        )
        
        logger.critical("Engagement emergency stop", reason=reason)