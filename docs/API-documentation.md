# API Documentation

This document provides comprehensive documentation for the Red Team Automation Framework REST API.

## Base URL

- **Development**: `http://localhost:8000`
## Authentication

Currently, the API does not require authentication. In production environments, implement proper authentication mechanisms.

## Response Format

All API responses follow a consistent JSON format:

```json
{
  "status": "success|error",
  "data": {},
  "message": "Optional message",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Health Check Endpoints

### GET /health

Basic health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### GET /api/v1/health

Detailed health check with system information.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Scope Management

### GET /api/v1/scope

Retrieve the current scope configuration.

**Response:**
```json
{
  "includes": {},
  "excludes": {},
  "engagement": {},
  "tools": {},
  "safety": {},
  "reporting": {}
}
```

### GET /api/v1/scope/current

Get the currently active scope.

**Response:**
```json
{
  "scope": {
    "name": "Example Engagement",
    "targets": [
      {
        "target": "example.com",
        "type": "domain",
        "notes": "Primary target"
      }
    ]
  }
}
```

### POST /api/v1/scope/upload

Upload a new scope configuration file.

**Parameters:**
- `file` (form-data): YAML scope file
- `name` (form-data, optional): Engagement name
- `validate` (form-data, optional): Whether to validate scope (default: true)

**Response:**
```json
{
  "status": "success",
  "message": "Scope uploaded and validated successfully",
  "scope": {
    "name": "Example Engagement",
    "targets": [...]
  }
}
```

## Burp Suite Integration

### POST /api/v1/burp/analyze

Analyze Burp Suite XML export files.

**Parameters:**
- `file` (form-data): Burp Suite XML file
- `feed_knowledge_base` (form-data, optional): Add findings to knowledge base (default: true)
- `analysis_type` (form-data, optional): Analysis type - "full", "findings_only", "knowledge_only" (default: "full")
- `scope_filter` (form-data, optional): Filter by current scope (default: true)

**Response:**
```json
{
  "status": "success",
  "message": "Burp analysis completed",
  "summary": {
    "total_issues": 25,
    "findings_created": 15,
    "knowledge_entries": 10,
    "analysis_duration": 12.5
  },
  "findings": [...],
  "knowledge_entries": [...]
}
```

## Engagement Management

### POST /api/v1/engagements/start

Start a new red team engagement.

**Request Body:**
```json
{
  "name": "Example Engagement",
  "target": "example.com",
  "scope": "YAML scope content",
  "scope_file_path": "/path/to/scope.yaml",
  "dry_run": false
}
```

**Response:**
```json
{
  "status": "success",
  "engagement_id": "eng_20240101_123456",
  "message": "Engagement started successfully",
  "details": {
    "name": "Example Engagement",
    "target": "example.com",
    "status": "running",
    "started_at": "2024-01-01T12:34:56Z"
  }
}
```

### GET /api/v1/engagements/{engagement_id}/status

Get the status of a specific engagement.

**Response:**
```json
{
  "engagement_id": "eng_20240101_123456",
  "status": "running",
  "progress": 45,
  "current_phase": "vulnerability_scanning",
  "started_at": "2024-01-01T12:34:56Z",
  "estimated_completion": "2024-01-01T15:30:00Z"
}
```

### GET /api/v1/engagements

List all engagements.

**Response:**
```json
{
  "engagements": [
    {
      "id": "eng_20240101_123456",
      "name": "Example Engagement",
      "status": "completed",
      "target": "example.com",
      "started_at": "2024-01-01T12:34:56Z",
      "completed_at": "2024-01-01T15:45:30Z"
    }
  ]
}
```

### DELETE /api/v1/engagements/{engagement_id}

Delete an engagement and its associated data.

**Response:**
```json
{
  "status": "success",
  "message": "Engagement deleted successfully"
}
```

## Findings Management

### GET /api/v1/findings

Retrieve all findings across engagements.

**Response:**
```json
{
  "findings": [
    {
      "id": "finding_123",
      "title": "SQL Injection",
      "severity": "high",
      "target": "example.com",
      "tool": "burp_suite",
      "description": "SQL injection vulnerability found",
      "timestamp": "2024-01-01T13:15:30Z",
      "ai_analysis": {
        "confidence": 0.95,
        "impact": "High risk of data breach",
        "remediation": "Implement parameterized queries"
      }
    }
  ]
}
```

### GET /api/v1/engagements/{engagement_id}/findings

Get findings for a specific engagement.

**Response:**
```json
{
  "engagement_id": "eng_20240101_123456",
  "findings": [...]
}
```

## Report Generation

### POST /api/v1/reports/generate

Generate a report for an engagement.

**Request Body:**
```json
{
  "engagement_id": "eng_20240101_123456",
  "format": "html",
  "use_ai": true
}
```

**Supported Formats:**
- `html` - Interactive HTML report
- `pdf` - PDF document
- `json` - Machine-readable JSON
- `md` - Markdown format

**Response:**
```json
{
  "status": "success",
  "report_id": "report_123",
  "message": "Report generated successfully",
  "download_url": "/api/v1/reports/report_123/download",
  "format": "html",
  "generated_at": "2024-01-01T16:00:00Z"
}
```

### GET /api/v1/reports

List all generated reports.

**Response:**
```json
{
  "reports": [
    {
      "id": "report_123",
      "engagement_id": "eng_20240101_123456",
      "format": "html",
      "generated_at": "2024-01-01T16:00:00Z",
      "download_url": "/api/v1/reports/report_123/download"
    }
  ]
}
```

### GET /api/v1/reports/{report_id}/download

Download a generated report.

**Response:** File download with appropriate content-type header.

## Knowledge Base

### GET /api/v1/knowledge

Retrieve knowledge base entries.

**Response:**
```json
{
  "entries": [
    {
      "id": "kb_001",
      "title": "SQL Injection Techniques",
      "category": "technique",
      "content": "Detailed explanation...",
      "tags": ["sql", "injection", "web"]
    }
  ]
}
```

### POST /api/v1/knowledge/search

Search the knowledge base.

**Request Body:**
```json
{
  "query": "SQL injection",
  "limit": 10,
  "category": "technique"
}
```

**Response:**
```json
{
  "results": [
    {
      "id": "kb_001",
      "title": "SQL Injection Techniques",
      "relevance_score": 0.95,
      "content": "..."
    }
  ]
}
```

## System Information

### GET /api/v1/system/stats

Get system statistics and performance metrics.

**Response:**
```json
{
  "active_engagements": 2,
  "total_findings": 150,
  "reports_generated": 25,
  "knowledge_entries": 500,
  "system_uptime": "2 days, 5 hours",
  "memory_usage": "45%",
  "disk_usage": "12GB"
}
```

### GET /api/v1/activity

Get recent system activity.

**Query Parameters:**
- `limit` (optional): Number of activities to return (default: 50)

**Response:**
```json
{
  "activities": [
    {
      "timestamp": "2024-01-01T16:30:00Z",
      "type": "engagement_started",
      "description": "New engagement started: Example Corp Assessment",
      "engagement_id": "eng_20240101_163000"
    }
  ]
}
```

## Scheduler Management

### GET /api/v1/scheduler/status

Get the status of the report scheduler.

**Response:**
```json
{
  "running": true,
  "active_tasks": 3,
  "completed_reports": 25,
  "auto_generation_enabled": true,
  "next_scheduled_run": "2024-01-01T18:00:00Z"
}
```

### POST /api/v1/engagements/{engagement_id}/enable-auto-reports

Enable automatic report generation for an engagement.

**Response:**
```json
{
  "status": "success",
  "message": "Auto-reports enabled for engagement"
}
```

## Error Handling

### Error Response Format

```json
{
  "status": "error",
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid scope configuration",
    "details": {
      "field": "targets",
      "issue": "At least one target is required"
    }
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Common Error Codes

- `VALIDATION_ERROR` - Request validation failed
- `NOT_FOUND` - Resource not found
- `ENGAGEMENT_NOT_FOUND` - Engagement ID not found
- `SCOPE_INVALID` - Scope configuration is invalid
- `FILE_PROCESSING_ERROR` - Error processing uploaded file
- `AI_SERVICE_ERROR` - AI service unavailable or error
- `RATE_LIMIT_EXCEEDED` - Rate limit exceeded
- `INTERNAL_ERROR` - Internal server error

### HTTP Status Codes

- `200` - Success
- `201` - Created
- `400` - Bad Request
- `404` - Not Found
- `422` - Unprocessable Entity
- `429` - Too Many Requests
- `500` - Internal Server Error

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Default Limit**: 60 requests per minute per IP
- **Headers**: Rate limit information is included in response headers
  - `X-RateLimit-Limit`: Request limit per window
  - `X-RateLimit-Remaining`: Remaining requests in current window
  - `X-RateLimit-Reset`: Time when the rate limit resets

## WebSocket Endpoints

### /ws/engagement/{engagement_id}

Real-time updates for engagement progress.

**Message Format:**
```json
{
  "type": "progress_update",
  "engagement_id": "eng_20240101_123456",
  "data": {
    "progress": 65,
    "current_phase": "report_generation",
    "message": "Generating HTML report..."
  }
}
```

## SDK and Client Libraries

Official client libraries are planned for:
- Python
- JavaScript/TypeScript
- Go
- Rust

## Changelog

### v1.0.0
- Initial API release
- Core engagement management
- Burp Suite integration
- Report generation
- Knowledge base functionality

---

**Note**: This API is under active development. Breaking changes may occur in minor versions until v1.0.0 is released.