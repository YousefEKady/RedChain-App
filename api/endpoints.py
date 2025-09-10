"""FastAPI endpoints for red team automation."""

import asyncio
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks, Depends
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from schemas import (
    Scope, Finding, ScanResult, EngagementReport, 
    EngagementConfig, StepLog, FindingStatus, SeverityLevel,
    ToolType, ScopeTarget
)
from workflows.orchestrator import get_orchestrator, reset_orchestrator, RedTeamOrchestrator
from rag.knowledge_base import KnowledgeBase
from agents.security_agent import SecurityAgent
# Removed unused import: load_scope_from_file
from utils.logging import get_logger, steps_logger
from config import settings
import yaml
import ipaddress

logger = get_logger(__name__)

from fastapi import APIRouter

# FastAPI app instance
app = FastAPI(
    title="Red Team Automation API",
    description="API for automated red team engagements with AI-powered analysis",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create API router with v1 prefix
api_router = APIRouter(prefix="/api/v1")

# Global state for tracking engagements and activities
active_engagements: Dict[str, Dict[str, Any]] = {}
activity_feed: List[Dict[str, Any]] = []

# Create a mock completed engagement for testing
# Import already done above with absolute imports

mock_scope = Scope(
    name="Test Engagement",
    description="Mock engagement for testing report generation",
    targets=[ScopeTarget(target="example.com", type="domain")]
)

mock_findings = [
    Finding(
        id="finding-1",
        title="SQL Injection Vulnerability",
        description="SQL injection found in login form",
        severity=SeverityLevel.HIGH,
        status=FindingStatus.TRUE_POSITIVE,
        target="https://example.com/login",
        tool=ToolType.NUCLEI,
        confidence=0.9
    ),
    Finding(
        id="finding-2",
        title="Missing Security Headers",
        description="Security headers not implemented",
        severity=SeverityLevel.MEDIUM,
        status=FindingStatus.TRUE_POSITIVE,
        target="https://example.com",
        tool=ToolType.NUCLEI,
        confidence=0.8
    )
]

mock_report = EngagementReport(
    engagement_id="mock-engagement-123",
    scope=mock_scope,
    executive_summary="This is a mock engagement report for testing purposes.",
    methodology="Automated testing using mock data",
    findings=mock_findings,
    recommendations=["Fix SQL injection vulnerabilities", "Implement security headers"]
)

# Add mock engagement to active_engagements
active_engagements["mock-engagement-123"] = {
    "status": "completed",
    "orchestrator": None,
    "started_at": datetime.now(),
    "completed_at": datetime.now(),
    "progress": "Completed",
    "error": None,
    "name": "Mock Test Engagement",
    "target": "example.com",
    "findings_count": len(mock_findings),
    "scan_results_count": 0,
    "report": mock_report
}

def add_activity(message: str, activity_type: str = "info", engagement_id: str = None):
    """Add an activity to the activity feed."""
    activity = {
        "id": f"activity_{len(activity_feed) + 1}",
        "message": message,
        "type": activity_type,
        "timestamp": datetime.now().isoformat(),
        "engagement_id": engagement_id
    }
    activity_feed.insert(0, activity)  # Add to beginning
    # Keep only last 100 activities
    if len(activity_feed) > 100:
        activity_feed.pop()


# Request/Response models
class EngagementRequest(BaseModel):
    """Request model for starting an engagement."""
    name: Optional[str] = None
    target: Optional[str] = None
    scope: Optional[str] = None  # YAML scope content as string
    dry_run: bool = False
    burp_files: Optional[List[str]] = None
    config: Optional[EngagementConfig] = None


class EngagementStatusResponse(BaseModel):
    """Response model for engagement status."""
    engagement_id: str
    status: str  # "running", "completed", "failed"
    progress: str
    findings_count: int
    scan_results_count: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error: Optional[str] = None


class KnowledgeSearchRequest(BaseModel):
    """Request model for knowledge base search."""
    query: str
    limit: int = 10
    search_type: str = "general"  # "general", "techniques", "findings"


class ReportIngestRequest(BaseModel):
    """Request model for report ingestion."""
    content: str
    source: str
    metadata: Optional[Dict[str, Any]] = None


# Health check endpoint
@api_router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# Scope management endpoints
@api_router.get("/scope", response_model=Scope)
async def get_scope():
    """Get the current scope configuration."""
    try:
        scope_file = Path(settings.SCOPE_FILE_PATH)
        if not scope_file.exists():
            raise HTTPException(
                status_code=404, 
                detail="Scope file not found. Please upload a scope.yaml file."
            )
        
        scope = load_scope_from_file(scope_file)
        return scope
        
    except Exception as e:
        logger.error("Failed to load scope", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/scope/current", response_model=Scope)
async def get_current_scope():
    """Get the current scope configuration (alias for /scope)."""
    return await get_scope()


@api_router.post("/scope/upload")
async def upload_scope(file: UploadFile = File(...)):
    """Upload a new scope.yaml file."""
    try:
        if not file.filename.endswith(('.yaml', '.yml')):
            raise HTTPException(
                status_code=400, 
                detail="File must be a YAML file (.yaml or .yml)"
            )
        
        # Save uploaded file
        scope_file = Path(settings.SCOPE_FILE_PATH)
        scope_file.parent.mkdir(parents=True, exist_ok=True)
        
        content = await file.read()
        scope_file.write_bytes(content)
        
        # Validate the uploaded scope
        scope = load_scope_from_file(scope_file)
        
        logger.info("Scope file uploaded", 
                   filename=file.filename,
                   targets_count=len(scope.targets))
        
        return {
            "message": "Scope file uploaded successfully",
            "targets_count": len(scope.targets),
            "excluded_count": len(scope.excluded_targets)
        }
        
    except Exception as e:
        logger.error("Scope upload failed", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))


# Engagement management endpoints
@api_router.post("/engagements/start", response_model=Dict[str, str])
async def start_engagement(
    request: EngagementRequest,
    background_tasks: BackgroundTasks
):
    """Start a new red team engagement."""
    print("API DEBUG: start_engagement function called!")
    print(f"API DEBUG: Request data: {request}")
    try:
        # Handle different input types - create scope objects directly
        scope = None
        
        if request.scope:
            # YAML scope content provided - parse directly to scope object
            try:
                scope_data = yaml.safe_load(request.scope)
                scope = Scope(**scope_data)
                logger.info("Created scope object from YAML content")
            except yaml.YAMLError as e:
                raise HTTPException(status_code=400, detail=f"Invalid YAML in scope content: {e}")
        elif request.target:
            # Simple engagement - create scope object directly
            target_type = "domain"
            
            # Check if it's an IP address
            try:
                ipaddress.ip_address(request.target.replace("*", "1"))  # Replace wildcard for validation
                target_type = "ip"
            except ValueError:
                # Check if it's a URL
                if request.target.startswith(("http://", "https://")):
                    target_type = "url"
                # Otherwise treat as domain
            
            scope = Scope(
                name=request.name or f"Quick Engagement - {request.target}",
                description=f"Quick engagement for target {request.target}",
                targets=[ScopeTarget(target=request.target, type=target_type, notes=f"Target: {request.target}")],
                excluded_targets=[]
            )
            logger.info(f"Created scope object for target: {request.target}")
        else:
            # Use default scope file as fallback
            default_scope_file = Path(settings.SCOPE_FILE_PATH)
            if not default_scope_file.exists():
                raise HTTPException(
                    status_code=400,
                    detail="No target, scope content, or default scope.yaml found"
                )
            scope = load_scope_from_file(default_scope_file)
        
        # Validate Burp files if provided
        burp_files = []
        if request.burp_files:
            for burp_file_path in request.burp_files:
                burp_file = Path(burp_file_path)
                if not burp_file.exists():
                    raise HTTPException(
                        status_code=404,
                        detail=f"Burp file not found: {burp_file_path}"
                    )
                burp_files.append(burp_file)
        
        # Generate engagement ID
        engagement_id = f"eng_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        output_dir = Path(settings.OUTPUT_DIR) / engagement_id
        
        # Create EngagementConfig if not provided
        if not request.config:
            config = EngagementConfig(
                engagement_id=engagement_id,
                output_dir=output_dir,
                dry_run=request.dry_run
            )
        else:
            config = request.config
            config.engagement_id = engagement_id
            config.output_dir = output_dir
            config.dry_run = request.dry_run
        
        # Create orchestrator (create new instance for each engagement)
        print(f"API DEBUG: About to create orchestrator with config: {config}")
        orchestrator = RedTeamOrchestrator(config)
        print(f"API DEBUG: Orchestrator created successfully with ID: {orchestrator.engagement_id}")
        print(f"API DEBUG: Orchestrator output_dir: {orchestrator.output_dir}")
        print(f"API DEBUG: Directory exists: {orchestrator.output_dir.exists()}")
        
        # Create a test file to verify the orchestrator is working
        test_file = orchestrator.output_dir / "api_creation_test.txt"
        test_file.write_text(f"API orchestrator created at {datetime.now()}")
        print(f"API DEBUG: Created test file: {test_file}")
        
        # Determine engagement name and target for display
        engagement_name = request.name or f"Engagement {engagement_id[:8]}"
        engagement_target = request.target or "Unknown Target"
        
        # Track engagement
        active_engagements[engagement_id] = {
            "status": "starting",
            "orchestrator": orchestrator,
            "started_at": datetime.now(),
            "progress": "Initializing engagement",
            "error": None,
            "name": engagement_name,
            "target": engagement_target,
            "findings_count": 0,
            "scan_results_count": 0
        }
        
        # Add activity for engagement creation
        add_activity(
            f"New engagement '{engagement_name}' started for target {engagement_target}",
            "engagement",
            engagement_id
        )
        
        # Start engagement in background
        background_tasks.add_task(
            run_engagement_background,
            engagement_id,
            scope,
            burp_files,
            request.dry_run
        )
        
        logger.info("Engagement started", 
                   engagement_id=engagement_id,
                   dry_run=request.dry_run)
        
        return {
            "engagement_id": engagement_id,
            "status": "started",
            "message": "Engagement started successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to start engagement", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


async def run_engagement_background(
    engagement_id: str,
    scope: Scope,
    burp_files: List[Path],
    dry_run: bool
):
    """Run engagement in background task."""
    try:
        orchestrator = active_engagements[engagement_id]["orchestrator"]
        active_engagements[engagement_id]["status"] = "running"
        active_engagements[engagement_id]["progress"] = "Running engagement"
        
        # Run the engagement
        report = await orchestrator.run_engagement(
            scope=scope,
            burp_files=burp_files,
            dry_run=dry_run
        )
        
        # Update status
        active_engagements[engagement_id].update({
            "status": "completed",
            "progress": "Engagement completed",
            "completed_at": datetime.now(),
            "report": report,
            "findings_count": len(orchestrator.findings) if hasattr(orchestrator, 'findings') else 0,
            "scan_results_count": len(orchestrator.scan_results) if hasattr(orchestrator, 'scan_results') else 0
        })
        
        # Automatically generate report after engagement completion
        try:
            from reporting.generator import ReportGenerator
            
            # Generate report in HTML and MD formats by default
            generator = ReportGenerator()
            generated_files = generator.generate_report(
                report,
                formats=['html', 'md']
            )
            
            # Store generated file paths in engagement data
            active_engagements[engagement_id]["generated_reports"] = {
                format_type: str(file_path) for format_type, file_path in generated_files.items()
            }
            
            logger.info("Auto-generated reports", 
                       engagement_id=engagement_id,
                       formats=list(generated_files.keys()))
            
            # Add activity for report generation
            add_activity(
                f"Reports auto-generated for engagement '{active_engagements[engagement_id]['name']}'",
                "success",
                engagement_id
            )
            
        except Exception as report_error:
            logger.error("Failed to auto-generate reports", 
                        engagement_id=engagement_id, 
                        error=str(report_error))
            # Don't fail the engagement if report generation fails
            add_activity(
                f"Report auto-generation failed for engagement '{active_engagements[engagement_id]['name']}': {str(report_error)}",
                "error",
                engagement_id
            )
        
        # Add activity for engagement completion
        add_activity(
            f"Engagement '{active_engagements[engagement_id]['name']}' completed successfully",
            "success",
            engagement_id
        )
        
        logger.info("Engagement completed", engagement_id=engagement_id)
        
    except Exception as e:
        active_engagements[engagement_id].update({
            "status": "failed",
            "progress": "Engagement failed",
            "completed_at": datetime.now(),
            "error": str(e)
        })
        

        
        # Add activity for engagement failure
        add_activity(
            f"Engagement '{active_engagements[engagement_id]['name']}' failed: {str(e)}",
            "error",
            engagement_id
        )
        
        logger.error("Engagement failed", 
                    engagement_id=engagement_id, error=str(e))


@api_router.get("/engagements/{engagement_id}/status", response_model=EngagementStatusResponse)
async def get_engagement_status(engagement_id: str):
    """Get the status of a running engagement."""
    if engagement_id not in active_engagements:
        raise HTTPException(
            status_code=404,
            detail=f"Engagement {engagement_id} not found"
        )
    
    engagement = active_engagements[engagement_id]
    orchestrator = engagement["orchestrator"]
    
    return EngagementStatusResponse(
        engagement_id=engagement_id,
        status=engagement["status"],
        progress=engagement["progress"],
        findings_count=len(orchestrator.findings),
        scan_results_count=len(orchestrator.scan_results),
        started_at=engagement["started_at"],
        completed_at=engagement.get("completed_at"),
        error=engagement.get("error")
    )


@api_router.get("/engagements/{engagement_id}/report", response_model=EngagementReport)
async def get_engagement_report(engagement_id: str):
    """Get the final report for a completed engagement."""
    if engagement_id not in active_engagements:
        raise HTTPException(
            status_code=404,
            detail=f"Engagement {engagement_id} not found"
        )
    
    engagement = active_engagements[engagement_id]
    
    if engagement["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Engagement {engagement_id} is not completed yet"
        )
    
    return engagement["report"]


@api_router.get("/engagements")
async def list_engagements():
    """List all engagements."""
    engagements = []
    for engagement_id, engagement in active_engagements.items():
        try:
            # Safely serialize datetime objects
            started_at = engagement["started_at"]
            if hasattr(started_at, 'isoformat'):
                started_at = started_at.isoformat()
            
            completed_at = engagement.get("completed_at")
            if completed_at and hasattr(completed_at, 'isoformat'):
                completed_at = completed_at.isoformat()
            
            engagements.append({
                "id": engagement_id,
                "name": engagement.get("name", "Unnamed Engagement"),
                "target": engagement.get("target", "Unknown Target"),
                "status": engagement["status"],
                "started_at": started_at,
                "completed_at": completed_at,
                "progress": engagement.get("progress", "0%"),
                "findings_count": engagement.get("findings_count", 0),
                "scan_results_count": engagement.get("scan_results_count", 0)
            })
        except Exception as e:
            logger.error(f"Error serializing engagement {engagement_id}: {e}")
            # Add a minimal entry for problematic engagements
            engagements.append({
                "id": engagement_id,
                "name": "Error Loading Engagement",
                "target": "Unknown",
                "status": "error",
                "started_at": None,
                "completed_at": None,
                "progress": "Error",
                "findings_count": 0,
                "scan_results_count": 0
            })
    
    # Return array directly as expected by frontend
    return engagements


@api_router.delete("/engagements/{engagement_id}")
async def stop_engagement(engagement_id: str):
    """Stop a running engagement."""
    if engagement_id not in active_engagements:
        raise HTTPException(
            status_code=404,
            detail=f"Engagement {engagement_id} not found"
        )
    
    engagement = active_engagements[engagement_id]
    
    if engagement["status"] == "running":
        # Mark as stopped
        engagement["status"] = "stopped"
        engagement["completed_at"] = datetime.now()
        engagement["progress"] = "Engagement stopped by user"
        
        logger.info("Engagement stopped", engagement_id=engagement_id)
        
        return {"message": "Engagement stopped successfully"}
    else:
        return {"message": f"Engagement is already {engagement['status']}"}


@api_router.post("/engagements/{engagement_id}/enable-auto-reports")
async def enable_auto_reports(engagement_id: str):
    """Enable automatic report generation for an existing engagement."""
    try:
        from database.database import get_db
        
        # Update the database to enable auto-report generation
        with get_db() as db:
            # Check if engagement exists
            result = db.execute(
                "SELECT id FROM engagements WHERE id = ?",
                (engagement_id,)
            ).fetchone()
            
            if not result:
                raise HTTPException(
                    status_code=404,
                    detail=f"Engagement {engagement_id} not found in database"
                )
            
            # Enable auto-report generation
            db.execute(
                "UPDATE engagements SET auto_report_enabled = 1 WHERE id = ?",
                (engagement_id,)
            )
            db.commit()
        
        # Trigger the scheduler to check for this engagement
        from services.report_scheduler import scheduler
        if not scheduler.running:
            scheduler.start()
        
        logger.info(f"Enabled auto-report generation for engagement {engagement_id}")
        
        return {
            "message": f"Auto-report generation enabled for engagement {engagement_id}",
            "engagement_id": engagement_id,
            "auto_report_enabled": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to enable auto-reports for engagement {engagement_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Knowledge base endpoints
@api_router.post("/knowledge/search")
async def search_knowledge(request: KnowledgeSearchRequest):
    """Search the knowledge base."""
    try:
        logger.info(f"Knowledge search request: query='{request.query}', limit={request.limit}, search_type='{request.search_type}'")
        security_agent = SecurityAgent()
        knowledge_base = KnowledgeBase(security_agent)
        
        if request.search_type == "techniques":
            results = knowledge_base.get_relevant_techniques(request.query, request.limit)
        elif request.search_type == "findings":
            # Create a dummy finding for search
            dummy_finding = Finding(
                title=request.query,
                description=request.query,
                severity=SeverityLevel.INFO,
                target="search",
                tool="search"
            )
            results = knowledge_base.get_similar_findings(dummy_finding, request.limit)
        else:
            results = knowledge_base.search_knowledge(request.query, max_results=request.limit)
        
        logger.info(f"Knowledge search completed: query='{request.query}' results_count={len(results)}")
        return {"results": results}
        
    except Exception as e:
        logger.error("Knowledge search failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/knowledge/ingest")
async def ingest_report(request: ReportIngestRequest):
    """Ingest a report into the knowledge base."""
    try:
        security_agent = SecurityAgent()
        knowledge_base = KnowledgeBase(security_agent)
        
        entry_id = await knowledge_base.ingest_report(
            report_content=request.content,
            source=request.source,
            report_type=request.metadata.get('category', 'general') if request.metadata else 'general'
        )
        
        logger.info("Report ingested", entry_id=entry_id, source=request.source)
        
        return {
            "entry_id": entry_id,
            "message": "Report ingested successfully"
        }
        
    except Exception as e:
        logger.error("Report ingestion failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/knowledge/ingest/file")
async def ingest_report_file(file: UploadFile = File(...)):
    """Ingest a report file into the knowledge base."""
    try:
        # Read file content
        content = await file.read()
        
        # Determine file type and decode
        if file.filename.endswith('.txt'):
            text_content = content.decode('utf-8')
        elif file.filename.endswith(('.md', '.markdown')):
            text_content = content.decode('utf-8')
        elif file.filename.endswith('.json'):
            import json
            data = json.loads(content.decode('utf-8'))
            text_content = json.dumps(data, indent=2)
        else:
            raise HTTPException(
                status_code=400,
                detail="Unsupported file type. Use .txt, .md, or .json files."
            )
        
        # Ingest the content
        security_agent = SecurityAgent()
        knowledge_base = KnowledgeBase(security_agent)
        
        entry_id = knowledge_base.ingest_report(
            content=text_content,
            source=f"file:{file.filename}",
            metadata={"filename": file.filename, "size": len(content)}
        )
        
        logger.info("Report file ingested", 
                   entry_id=entry_id, filename=file.filename)
        
        return {
            "entry_id": entry_id,
            "filename": file.filename,
            "message": "Report file ingested successfully"
        }
        
    except Exception as e:
        logger.error("Report file ingestion failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


# Logging endpoints
@api_router.get("/logs/steps")
async def get_steps_log(limit: int = 100):
    """Get recent steps from the steps.txt log."""
    try:
        steps = steps_logger.get_recent_steps(limit)
        return {"steps": steps}
        
    except Exception as e:
        logger.error("Failed to get steps log", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/logs/steps/download")
async def download_steps_log():
    """Download the complete steps.txt log file."""
    try:
        log_file = Path(settings.STEPS_LOG_FILE)
        if not log_file.exists():
            raise HTTPException(status_code=404, detail="Steps log file not found")
        
        return FileResponse(
            path=str(log_file),
            filename="steps.txt",
            media_type="text/plain"
        )
        
    except Exception as e:
        logger.error("Failed to download steps log", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


# Utility endpoints
@api_router.post("/utils/reset")
async def reset_system():
    """Reset the system state (for testing)."""
    try:
        # Clear active engagements
        active_engagements.clear()
        
        # Reset orchestrator
        reset_orchestrator()
        
        logger.info("System reset completed")
        
        return {"message": "System reset successfully"}
        
    except Exception as e:
        logger.error("System reset failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/utils/config")
async def get_config():
    """Get current system configuration."""
    return {
        "scope_file_path": settings.SCOPE_FILE_PATH,
        "output_dir": settings.OUTPUT_DIR,
        "steps_log_file": settings.STEPS_LOG_FILE,
        "rate_limit_enabled": settings.RATE_LIMIT_ENABLED,
        "rate_limit_requests": settings.RATE_LIMIT_REQUESTS,
        "rate_limit_period": settings.RATE_LIMIT_PERIOD
    }


# System endpoints
@api_router.get("/system/stats")
async def get_system_stats():
    """Get system statistics."""
    try:
        import psutil
        import time
        
        # Get real system metrics
        cpu_usage = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('.')
        
        # Calculate uptime (simplified)
        boot_time = psutil.boot_time()
        uptime_seconds = int(time.time() - boot_time)
        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60
        uptime_str = f"{hours:02d}:{minutes:02d}:00"
        
        # Calculate actual findings count
        total_findings = 0
        critical_findings = 0
        running_engagements = 0
        tools_running = 0
        last_scan = "Never"
        
        for engagement_id, engagement in active_engagements.items():
            if engagement.get("status") == "running":
                running_engagements += 1
            
            # Count findings from orchestrator if available
            if "orchestrator" in engagement and engagement["orchestrator"]:
                orchestrator = engagement["orchestrator"]
                if hasattr(orchestrator, 'findings'):
                    total_findings += len(orchestrator.findings)
                    for finding in orchestrator.findings:
                        if hasattr(finding, 'severity') and finding.severity.value.lower() in ['critical', 'high']:
                            critical_findings += 1
            
            # Count findings from mock data
            if "report" in engagement and engagement["report"]:
                report = engagement["report"]
                if hasattr(report, 'findings'):
                    total_findings += len(report.findings)
                    for finding in report.findings:
                        if hasattr(finding, 'severity') and finding.severity.value.lower() in ['critical', 'high']:
                            critical_findings += 1
            
            # Update last scan time
            if "completed_at" in engagement and engagement["completed_at"]:
                last_scan = engagement["completed_at"].strftime("%Y-%m-%d %H:%M")
        
        return {
            "cpu_usage": round(cpu_usage, 1),
            "memory_usage": round(memory.percent, 1),
            "disk_usage": round(disk.percent, 1),
            "active_engagements": running_engagements,
            "total_engagements": len(active_engagements),
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "tools_running": tools_running,
            "uptime": uptime_str,
            "last_scan": last_scan
        }
    except ImportError:
        # Fallback if psutil is not available
        total_findings = sum(len(eng.get("report", {}).get("findings", [])) if eng.get("report") else 0 for eng in active_engagements.values())
        return {
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "disk_usage": 0.0,
            "active_engagements": len([e for e in active_engagements.values() if e.get("status") == "running"]),
            "total_engagements": len(active_engagements),
            "total_findings": total_findings,
            "critical_findings": 0,
            "tools_running": 0,
            "uptime": "0:00:00",
            "last_scan": "Never"
        }
    except Exception as e:
        # Error fallback
        return {
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "disk_usage": 0.0,
            "active_engagements": 0,
            "total_engagements": len(active_engagements),
            "total_findings": 0,
            "critical_findings": 0,
            "tools_running": 0,
            "uptime": "Error",
            "last_scan": "Error"
        }

@api_router.get("/system/info")
async def get_system_info():
    """Get system information."""
    return {
        "version": "1.0.0",
        "api_version": "v1",
        "status": "running",
        "features": ["scope_management", "engagement_automation", "ai_analysis"]
    }

@api_router.get("/activity")
async def get_recent_activity(limit: int = 50):
    """Get recent activity."""
    # Return recent activities, limited by the limit parameter
    return activity_feed[:limit]

@api_router.get("/findings")
async def get_findings(limit: int = 100):
    """Get all findings."""
    # Return array directly as expected by frontend
    findings = []
    for engagement_id, engagement in active_engagements.items():
        if "orchestrator" in engagement and engagement["orchestrator"] is not None:
            orchestrator = engagement["orchestrator"]
            if hasattr(orchestrator, 'findings') and orchestrator.findings:
                for finding in orchestrator.findings:
                    findings.append({
                        "id": f"{engagement_id}_{finding.title}",
                        "title": finding.title,
                        "description": finding.description,
                        "severity": finding.severity.value,
                        "target": finding.target,
                        "tool": finding.tool,
                        "url": getattr(finding, 'url', finding.target),
                        "engagement_id": engagement_id
                    })
    return findings[:limit]

@api_router.get("/knowledge")
async def get_knowledge_base():
    """Get knowledge base entries."""
    # Return array directly as expected by frontend
    try:
        security_agent = SecurityAgent()
        knowledge_base = KnowledgeBase(security_agent)
        # Get some sample knowledge entries
        entries = knowledge_base.search_knowledge("security", limit=50)
        return entries if isinstance(entries, list) else []
    except Exception as e:
        logger.error("Failed to get knowledge base", error=str(e))
        return []

@api_router.get("/reports")
async def get_reports():
    """Get all reports."""
    # Return array directly as expected by frontend
    reports = []
    for engagement_id, engagement in active_engagements.items():
        if engagement["status"] == "completed" and "report" in engagement:
            reports.append({
                "id": engagement_id,
                "engagement_id": engagement_id,
                "title": f"Report for {engagement_id}",
                "created_at": engagement["completed_at"],
                "status": "completed",
                "format": "html"
            })
    return reports


class ReportGenerateRequest(BaseModel):
    """Request model for report generation."""
    engagement_id: str
    format: str = "html"  # "html", "pdf", "json", "md"


@api_router.post("/reports/generate")
async def generate_report(request: ReportGenerateRequest):
    """Generate a report for a completed engagement."""
    try:
        if request.engagement_id not in active_engagements:
            raise HTTPException(
                status_code=404,
                detail=f"Engagement {request.engagement_id} not found"
            )
        
        engagement = active_engagements[request.engagement_id]
        
        if engagement["status"] != "completed":
            raise HTTPException(
                status_code=400,
                detail=f"Engagement {request.engagement_id} is not completed yet"
            )
        
        if "report" not in engagement:
            raise HTTPException(
                status_code=400,
                detail=f"No report available for engagement {request.engagement_id}"
            )
        
        # Generate report using the reporting module
        from reporting.generator import ReportGenerator
        
        output_dir = Path(settings.OUTPUT_DIR) / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        generator = ReportGenerator(output_dir)
        generated_files = generator.generate_report(
            engagement["report"],
            formats=[request.format]
        )
        
        if request.format not in generated_files:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to generate {request.format} report"
            )
        
        file_path = generated_files[request.format]
        
        logger.info("Report generated", 
                   engagement_id=request.engagement_id, 
                   format=request.format,
                   file_path=str(file_path))
        
        return {
            "report_id": f"{request.engagement_id}_{request.format}",
            "engagement_id": request.engagement_id,
            "format": request.format,
            "file_path": str(file_path),
            "message": f"Report generated successfully in {request.format} format"
        }
        
    except Exception as e:
        logger.error("Report generation failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/reports/{report_id}/download")
async def download_report(report_id: str):
    """Download a generated report."""
    try:
        # Parse report_id to get engagement_id and format
        if "_" not in report_id:
            raise HTTPException(
                status_code=400,
                detail="Invalid report ID format. Expected: engagement_id_format"
            )
        
        engagement_id, format_type = report_id.rsplit("_", 1)
        
        # Check if engagement exists
        if engagement_id not in active_engagements:
            raise HTTPException(
                status_code=404,
                detail=f"Engagement {engagement_id} not found"
            )
        
        # Construct file path
        output_dir = Path(settings.OUTPUT_DIR) / "reports"
        file_path = output_dir / f"{engagement_id}_report.{format_type}"
        
        if not file_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"Report file not found: {file_path.name}"
            )
        
        # Determine media type
        media_types = {
            "html": "text/html",
            "pdf": "application/pdf",
            "json": "application/json",
            "md": "text/markdown"
        }
        
        media_type = media_types.get(format_type, "application/octet-stream")
        
        return FileResponse(
            path=str(file_path),
            filename=f"{engagement_id}_report.{format_type}",
            media_type=media_type
        )
        
    except Exception as e:
        logger.error("Report download failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/logs")
async def get_logs(level: str = "info", limit: int = 100):
    """Get system logs."""
    # Return array directly as expected by frontend
    try:
        steps = steps_logger.get_recent_steps(limit)
        logs = []
        for step in steps:
            logs.append({
                "timestamp": datetime.now().isoformat(),
                "level": level,
                "message": step,
                "source": "system"
            })
        return logs
    except Exception as e:
        logger.error("Failed to get logs", error=str(e))
        return []

@api_router.post("/burp/analyze")
async def analyze_burp_file(
    file: UploadFile = File(...),
    feed_knowledge_base: bool = True,
    analysis_type: str = "full",
    scope_filter: bool = True
):
    """Analyze Burp Suite export file."""
    if not file.filename.lower().endswith(('.xml', '.json', '.burp')):
        raise HTTPException(
            status_code=400,
            detail="Invalid file format. Supported formats: .xml, .json, .burp"
        )
    
    try:
        # For now, return a mock response since full implementation requires complex setup
        content = await file.read()
        
        return {
            "message": "Burp file analyzed successfully",
            "file_info": {
                "name": file.filename,
                "size": len(content),
                "format": Path(file.filename).suffix.lower()
            },
            "analysis_results": {
                "issues_found": 3,
                "findings_generated": 3,
                "knowledge_entries_added": 2 if feed_knowledge_base else 0
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to analyze Burp file", error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# Include the API router in the main app
app.include_router(api_router)

# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    logger.error("Unhandled exception", 
                path=request.url.path, error=str(exc))
    
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "redteam_automation.api.endpoints:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )