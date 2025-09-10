"""Configuration module for red team automation framework."""

import os
import warnings
from pathlib import Path
from typing import Optional

from pydantic import Field, validator
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Security warning for development environment
if os.getenv('GOOGLE_API_KEY') == 'your_google_api_key_here':
    warnings.warn(
        "Using default API key placeholder. Please set a real GOOGLE_API_KEY in your .env file.",
        UserWarning
    )

class Settings(BaseSettings):
    """Application settings."""
    
    # API Keys
    google_api_key: str = Field(..., env="GOOGLE_API_KEY")
    
    # Model Configuration
    gemini_model: str = Field(default="gemini-2.0-flash", env="GEMINI_MODEL")
    model_temperature: float = Field(default=0.1, env="MODEL_TEMPERATURE")
    max_tokens: int = Field(default=4096, env="MAX_TOKENS")
    
    # Project Discovery Tools
    subfinder_path: Optional[str] = Field(default=None, env="SUBFINDER_PATH")
    httpx_path: Optional[str] = Field(default=None, env="HTTPX_PATH")
    nuclei_path: Optional[str] = Field(default=None, env="NUCLEI_PATH")
    nuclei_templates_path: Optional[str] = Field(default=None, env="NUCLEI_TEMPLATES_PATH")
    projectdiscovery_api_key: Optional[str] = Field(default=None, env="PROJECTDISCOVERY_API_KEY")
    projectdiscovery_team_id: Optional[str] = Field(default=None, env="PROJECTDISCOVERY_TEAM_ID")
    
    # Rate Limiting
    rate_limit_rpm: int = Field(default=60, env="RATE_LIMIT_RPM")
    rate_limit_delay: float = Field(default=1.0, env="RATE_LIMIT_DELAY")
    
    # Database
    vector_db_path: str = Field(default="./data/vector_db", env="VECTOR_DB_PATH")
    
    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    steps_log_file: str = Field(default="steps.txt", env="STEPS_LOG_FILE")
    
    # Output
    output_dir: str = Field(default="./output_external", env="OUTPUT_DIR")
    reports_dir: str = Field(default="./reports_external", env="REPORTS_DIR")
    
    # Safety
    scope_file: str = Field(default="scope.yaml", env="SCOPE_FILE")
    require_scope: bool = Field(default=True, env="REQUIRE_SCOPE")
    
    # Automatic Report Generation
    auto_generate_reports: bool = Field(default=True, env="AUTO_GENERATE_REPORTS")
    auto_report_formats: str = Field(default="html,markdown", env="AUTO_REPORT_FORMATS")
    auto_report_on_completion: bool = Field(default=True, env="AUTO_REPORT_ON_COMPLETION")
    auto_report_schedule: Optional[str] = Field(default=None, env="AUTO_REPORT_SCHEDULE")  # cron format
    report_notification_webhook: Optional[str] = Field(default=None, env="REPORT_NOTIFICATION_WEBHOOK")
    batch_report_generation: bool = Field(default=False, env="BATCH_REPORT_GENERATION")
    max_concurrent_reports: int = Field(default=3, env="MAX_CONCURRENT_REPORTS")
    
    @validator('google_api_key')
    def validate_api_key(cls, v):
        """Validate Google API key is not a placeholder."""
        if not v or v == 'your_google_api_key_here':
            raise ValueError("Google API key must be set and cannot be the placeholder value")
        if len(v) < 20:  # Basic length check for API keys
            raise ValueError("Google API key appears to be too short")
        return v
    
    @validator('model_temperature')
    def validate_temperature(cls, v):
        """Validate model temperature is within acceptable range."""
        if not 0.0 <= v <= 2.0:
            raise ValueError("Model temperature must be between 0.0 and 2.0")
        return v
    
    @validator('max_tokens')
    def validate_max_tokens(cls, v):
        """Validate max tokens is reasonable."""
        if v <= 0 or v > 100000:
            raise ValueError("Max tokens must be between 1 and 100000")
        return v
    
    @validator('rate_limit_rpm')
    def validate_rate_limit(cls, v):
        """Validate rate limit is reasonable."""
        if v <= 0 or v > 10000:
            raise ValueError("Rate limit RPM must be between 1 and 10000")
        return v
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level is valid."""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {', '.join(valid_levels)}")
        return v.upper()
    
    @validator('auto_report_formats')
    def validate_report_formats(cls, v):
        """Validate report formats are valid."""
        if not v:
            return v
        valid_formats = ['html', 'markdown', 'pdf', 'json']
        formats = [f.strip().lower() for f in v.split(',')]
        for fmt in formats:
            if fmt not in valid_formats:
                raise ValueError(f"Invalid report format '{fmt}'. Valid formats: {', '.join(valid_formats)}")
        return ','.join(formats)
    
    @validator('max_concurrent_reports')
    def validate_max_concurrent_reports(cls, v):
        """Validate max concurrent reports is reasonable."""
        if v <= 0 or v > 10:
            raise ValueError("Max concurrent reports must be between 1 and 10")
        return v
    
    @property
    def SCOPE_FILE_PATH(self) -> str:
        """Get the full path to the scope file."""
        return self.scope_file
    
    @property
    def OUTPUT_DIR(self) -> str:
        """Get the output directory."""
        return self.output_dir
    
    @property
    def STEPS_LOG_FILE(self) -> str:
        """Get the steps log file path."""
        return self.steps_log_file
    
    @property
    def RATE_LIMIT_ENABLED(self) -> bool:
        """Check if rate limiting is enabled."""
        return True
    
    @property
    def RATE_LIMIT_REQUESTS(self) -> int:
        """Get rate limit requests per period."""
        return self.rate_limit_rpm
    
    @property
    def RATE_LIMIT_PERIOD(self) -> int:
        """Get rate limit period in seconds."""
        return 60
    
    @property
    def VECTOR_DB_PATH(self) -> str:
        """Get the vector database path."""
        return self.vector_db_path
    
    @property
    def SQLITE_DB_PATH(self) -> str:
        """Get the SQLite database path."""
        return "./data/database.db"
    
    @property
    def CHROMA_DB_PATH(self) -> str:
        """Get the Chroma database path."""
        return self.vector_db_path
    
    @property
    def GEMINI_MODEL(self) -> str:
        """Get the Gemini model name."""
        return self.gemini_model
    
    @property
    def model_name(self) -> str:
        """Get the model name."""
        return self.gemini_model
    
    @property
    def temperature(self) -> float:
        """Get the model temperature."""
        return self.model_temperature
    
    @property
    def max_tokens(self) -> int:
        """Get the max tokens."""
        return self.max_tokens
    
    @property
    def rate_limit_requests_per_minute(self) -> int:
        """Get rate limit requests per minute."""
        return self.rate_limit_rpm
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
settings = Settings()

# Ensure required directories exist
Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
Path(settings.reports_dir).mkdir(parents=True, exist_ok=True)
Path(settings.vector_db_path).parent.mkdir(parents=True, exist_ok=True)