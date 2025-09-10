"""Scope validation utilities for safety checks."""

import ipaddress
import re
from pathlib import Path
from typing import List, Set, Tuple
from urllib.parse import urlparse

import yaml

from schemas import Scope, ScopeTarget
from utils.logging import get_logger, steps_logger

logger = get_logger(__name__)


def _normalize_scope_format(scope_data: dict) -> dict:
    """Normalize different scope formats to the standard format.
    
    Args:
        scope_data: Raw scope data from YAML
        
    Returns:
        Normalized scope data
    """
    # If targets is already a list of ScopeTarget objects, return as-is
    if isinstance(scope_data.get('targets'), list):
        return scope_data
        
    # Handle included_targets/excluded_targets format
    if 'included_targets' in scope_data:
        normalized_targets = []
        normalized_excluded = []
        
        # Convert included targets
        for target_item in scope_data['included_targets']:
            if isinstance(target_item, dict) and 'value' in target_item:
                normalized_targets.append({
                    'target': target_item['value'],
                    'type': target_item.get('type', 'domain'),
                    'notes': target_item.get('description')
                })
        
        # Convert excluded targets
        if 'excluded_targets' in scope_data:
            for target_item in scope_data['excluded_targets']:
                if isinstance(target_item, dict) and 'value' in target_item:
                    normalized_excluded.append(target_item['value'])
                elif isinstance(target_item, str):
                    normalized_excluded.append(target_item)
        
        scope_data['targets'] = normalized_targets
        scope_data['excluded_targets'] = normalized_excluded
        
        # Remove the old format keys
        scope_data.pop('included_targets', None)
        
    # Handle nested format (like rayashop scope)
    elif isinstance(scope_data.get('targets'), dict):
        targets_dict = scope_data['targets']
        normalized_targets = []
        
        # Convert domains
        if 'domains' in targets_dict:
            for domain in targets_dict['domains']:
                normalized_targets.append({
                    'target': domain,
                    'type': 'domain',
                    'notes': None
                })
                
        # Convert IP ranges
        if 'ip_ranges' in targets_dict:
            for ip_range in targets_dict['ip_ranges']:
                if ip_range == 'auto-discover':
                    # Skip auto-discover for now
                    continue
                normalized_targets.append({
                    'target': ip_range,
                    'type': 'ip',
                    'notes': None
                })
                
        scope_data['targets'] = normalized_targets
        
    # Ensure we have required fields with defaults
    if 'name' not in scope_data:
        scope_data['name'] = 'Red Team Engagement'
    if 'description' not in scope_data:
        scope_data['description'] = 'Automated red team engagement'
    if 'excluded_targets' not in scope_data:
        scope_data['excluded_targets'] = []
        
    return scope_data


class ScopeValidator:
    """Validates targets against defined scope to ensure authorized testing."""
    
    def __init__(self, scope: Scope):
        self.scope = scope
        self.allowed_domains = set()
        self.allowed_ips = set()
        self.allowed_networks = set()
        self.excluded_targets = set(scope.excluded_targets)
        
        self._parse_scope_targets()
        
    def _parse_scope_targets(self) -> None:
        """Parse scope targets into different categories."""
        for target in self.scope.targets:
            target_value = target.target.lower().strip()
            
            if target.type == "domain":
                # Handle wildcard domains
                if target_value.startswith("*."):
                    self.allowed_domains.add(target_value[2:])  # Remove *.
                else:
                    self.allowed_domains.add(target_value)
                    
            elif target.type == "ip":
                try:
                    # Check if it's a network range
                    if "/" in target_value:
                        network = ipaddress.ip_network(target_value, strict=False)
                        self.allowed_networks.add(network)
                    else:
                        ip = ipaddress.ip_address(target_value)
                        self.allowed_ips.add(ip)
                except ValueError as e:
                    logger.warning(f"Invalid IP address in scope: {target_value}", error=str(e))
                    
            elif target.type == "url":
                parsed = urlparse(target_value)
                if parsed.hostname:
                    self.allowed_domains.add(parsed.hostname.lower())
                    
    def is_target_in_scope(self, target: str) -> Tuple[bool, str]:
        """Check if a target is within the defined scope.
        
        Args:
            target: Target to validate (domain, IP, or URL)
            
        Returns:
            Tuple of (is_valid, reason)
        """
        # Input validation
        if not target or not isinstance(target, str):
            logger.warning("Target must be a non-empty string")
            return False, "Target must be a non-empty string"
            
        target = target.strip()
        if not target:
            logger.warning("Target cannot be empty or whitespace only")
            return False, "Target cannot be empty or whitespace only"
            
        target = target.lower()
        
        # Check if target is explicitly excluded
        if target in self.excluded_targets:
            return False, f"Target {target} is explicitly excluded from scope"
            
        # Parse target to determine type
        if self._is_ip_address(target):
            return self._validate_ip_target(target)
        elif self._is_url(target):
            return self._validate_url_target(target)
        else:
            return self._validate_domain_target(target)
            
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address."""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
            
    def _is_url(self, target: str) -> bool:
        """Check if target is a URL."""
        return target.startswith(("http://", "https://"))
        
    def _validate_ip_target(self, target: str) -> Tuple[bool, str]:
        """Validate IP address target."""
        try:
            ip = ipaddress.ip_address(target)
            
            # Check direct IP match
            if ip in self.allowed_ips:
                return True, "IP address is in scope"
                
            # Check network ranges
            for network in self.allowed_networks:
                if ip in network:
                    return True, f"IP address is in allowed network {network}"
                    
            return False, f"IP address {target} is not in scope"
            
        except ValueError:
            return False, f"Invalid IP address: {target}"
            
    def _validate_url_target(self, target: str) -> Tuple[bool, str]:
        """Validate URL target."""
        parsed = urlparse(target)
        if not parsed.hostname:
            return False, "URL does not contain a valid hostname"
            
        return self._validate_domain_target(parsed.hostname)
        
    def _validate_domain_target(self, target: str) -> Tuple[bool, str]:
        """Validate domain target."""
        target = target.lower()
        
        # Direct domain match
        if target in self.allowed_domains:
            return True, "Domain is in scope"
            
        # Check wildcard matches
        for allowed_domain in self.allowed_domains:
            if target.endswith(f".{allowed_domain}"):
                return True, f"Domain matches wildcard scope: *.{allowed_domain}"
                
        return False, f"Domain {target} is not in scope"
        
    def validate_target_list(self, targets: List[str]) -> Tuple[List[str], List[str]]:
        """Validate a list of targets.
        
        Args:
            targets: List of targets to validate
            
        Returns:
            Tuple of (valid_targets, invalid_targets_with_reasons)
        """
        valid_targets = []
        invalid_targets = []
        
        for target in targets:
            is_valid, reason = self.is_target_in_scope(target)
            if is_valid:
                valid_targets.append(target)
                logger.info(f"Target validated: {target}", reason=reason)
            else:
                invalid_targets.append(f"{target}: {reason}")
                logger.warning(f"Target rejected: {target}", reason=reason)
                
        return valid_targets, invalid_targets
        
    def get_scope_summary(self) -> dict:
        """Get a summary of the current scope configuration."""
        return {
            "engagement_name": self.scope.name,
            "total_targets": len(self.scope.targets),
            "allowed_domains": len(self.allowed_domains),
            "allowed_ips": len(self.allowed_ips),
            "allowed_networks": len(self.allowed_networks),
            "excluded_targets": len(self.excluded_targets),
            "domains": list(self.allowed_domains),
            "ips": [str(ip) for ip in self.allowed_ips],
            "networks": [str(net) for net in self.allowed_networks],
            "excluded": list(self.excluded_targets)
        }


def load_scope_from_file(scope_file: Path) -> Scope:
    """Load scope configuration from YAML file.
    
    Args:
        scope_file: Path to scope.yaml file
        
    Returns:
        Parsed Scope object
        
    Raises:
        FileNotFoundError: If scope file doesn't exist
        ValueError: If scope file is invalid
    """
    # Input validation
    if not scope_file:
        raise ValueError("Scope file path cannot be None or empty")
        
    if not scope_file.exists():
        raise FileNotFoundError(f"Scope file not found: {scope_file}")
        
    if not scope_file.is_file():
        raise ValueError(f"Scope path is not a file: {scope_file}")
        
    try:
        with open(scope_file, 'r', encoding='utf-8') as f:
            scope_data = yaml.safe_load(f)
            
        if not scope_data:
            raise ValueError(f"Empty scope file: {scope_file}")
            
        # Handle different scope formats
        scope_data = _normalize_scope_format(scope_data)
        
        scope = Scope(**scope_data)
        
        steps_logger.log_step(
            "initialization", 
            f"Scope loaded from {scope_file}",
            "completed",
            f"Loaded {len(scope.targets)} targets for engagement '{scope.name}'"
        )
        
        logger.info(f"Scope loaded successfully", 
                   file=str(scope_file), 
                   targets=len(scope.targets),
                   engagement=scope.name)
        
        return scope
        
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in scope file: {e}")
    except PermissionError as e:
        raise ValueError(f"Permission denied accessing scope file {scope_file}: {e}")
    except UnicodeDecodeError as e:
        raise ValueError(f"Encoding error reading scope file {scope_file}: {e}")
    except Exception as e:
        raise ValueError(f"Error parsing scope file: {e}")


def validate_scope_file_exists(scope_file: Path) -> bool:
    """Check if scope file exists and log the result.
    
    Args:
        scope_file: Path to scope.yaml file
        
    Returns:
        True if file exists, False otherwise
    """
    exists = scope_file.exists()
    
    if exists:
        steps_logger.log_step(
            "initialization",
            "Scope file validation",
            "completed",
            f"Scope file found: {scope_file}"
        )
        logger.info("Scope file validation passed", file=str(scope_file))
    else:
        steps_logger.log_step(
            "initialization",
            "Scope file validation",
            "failed",
            f"Scope file not found: {scope_file}"
        )
        logger.error("Scope file validation failed", file=str(scope_file))
        
    return exists