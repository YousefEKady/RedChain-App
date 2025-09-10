"""Knowledge base system for report ingestion and retrieval."""

import re
import json
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document

from schemas import KnowledgeEntry, Finding, EngagementReport
from agents.security_agent import SecurityAgent
from utils.logging import get_logger, steps_logger
from .vector_store import get_vector_store

logger = get_logger(__name__)


class KnowledgeBase:
    """Knowledge base for ingesting and retrieving security knowledge."""
    
    def __init__(self, security_agent: SecurityAgent):
        """Initialize the knowledge base.
        
        Args:
            security_agent: SecurityAgent for LLM operations
        """
        self.security_agent = security_agent
        self.vector_store = get_vector_store()
        
        # Text splitter for chunking large documents
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            length_function=len,
            separators=["\n\n", "\n", ".", "!", "?", ",", " ", ""]
        )
        
        logger.info("Knowledge base initialized")
        
    async def ingest_report(self, report_content: str, source: str, 
                     report_type: str = "manual") -> List[str]:
        """Ingest a security report into the knowledge base.
        
        Args:
            report_content: The content of the report
            source: Source of the report (e.g., file name, URL)
            report_type: Type of report (manual, automated, etc.)
            
        Returns:
            List of knowledge entry IDs that were created
        """
        steps_logger.log_step(
            "knowledge_ingestion",
            f"Ingesting report from {source}",
            "started",
            f"Type: {report_type}, Length: {len(report_content)} chars"
        )
        
        try:
            # Extract knowledge from the report using the security agent
            extracted_knowledge = await self.security_agent.extract_knowledge_from_report(
                report_content, source
            )
            
            entry_ids = []
            
            # Process each extracted knowledge item
            for knowledge_entry in extracted_knowledge:
                try:
                    # Add to vector store
                    entry_id = self.vector_store.add_knowledge_entry(knowledge_entry)
                    entry_ids.append(entry_id)
                    
                except Exception as e:
                    logger.warning("Failed to process knowledge item", 
                                  item=knowledge_entry, error=str(e))
                    continue
                    
            # Also chunk and store the raw report for reference
            raw_entry_id = self._store_raw_report(report_content, source, report_type)
            if raw_entry_id:
                entry_ids.append(raw_entry_id)
                
            steps_logger.log_step(
                "knowledge_ingestion",
                f"Report ingestion completed",
                "completed",
                f"Created {len(entry_ids)} knowledge entries"
            )
            
            logger.info("Report ingested successfully", 
                       source=source,
                       entries_created=len(entry_ids))
            
            return entry_ids
            
        except Exception as e:
            steps_logger.log_step(
                "knowledge_ingestion",
                f"Report ingestion failed",
                "failed",
                f"Error: {str(e)}"
            )
            logger.error("Report ingestion failed", source=source, error=str(e))
            raise
            
    def ingest_report_file(self, file_path: Path) -> List[str]:
        """Ingest a report from a file.
        
        Args:
            file_path: Path to the report file
            
        Returns:
            List of knowledge entry IDs that were created
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Report file not found: {file_path}")
            
        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            # Try with different encoding
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
                
        # Determine report type from file extension
        report_type = self._determine_report_type(file_path)
        
        return self.ingest_report(content, str(file_path), report_type)
        
    def search_knowledge(self, query: str, knowledge_type: Optional[str] = None,
                        max_results: int = 5) -> List[Dict[str, Any]]:
        """Search the knowledge base.
        
        Args:
            query: Search query
            knowledge_type: Optional filter by knowledge type
            max_results: Maximum number of results to return
            
        Returns:
            List of relevant knowledge entries
        """
        try:
            # Build filters
            filters = {}
            if knowledge_type:
                filters["category"] = knowledge_type
                
            # Search vector store
            results = self.vector_store.search_knowledge(
                query=query,
                n_results=max_results,
                filters=filters
            )
            
            logger.debug("Knowledge search completed", 
                        query=query, results_count=len(results))
            
            return results
            
        except Exception as e:
            logger.error("Knowledge search failed", query=query, error=str(e))
            return []
            
    def get_relevant_techniques(self, finding: Finding, 
                               max_results: int = 3) -> List[Dict[str, Any]]:
        """Get relevant techniques for a finding.
        
        Args:
            finding: Finding to get techniques for
            max_results: Maximum number of results
            
        Returns:
            List of relevant technique knowledge entries
        """
        try:
            # Create search query from finding
            query_parts = [finding.title, finding.description]
            if finding.cve_id:
                query_parts.append(finding.cve_id)
                
            query = " ".join(query_parts)
            
            # Search for techniques
            results = self.search_knowledge(
                query=query,
                knowledge_type="technique",
                max_results=max_results
            )
            
            logger.debug("Retrieved relevant techniques", 
                        finding_id=finding.id, techniques_count=len(results))
            
            return results
            
        except Exception as e:
            logger.error("Failed to get relevant techniques", 
                        finding_id=finding.id, error=str(e))
            return []
            
    def get_similar_findings_context(self, finding: Finding, 
                                   max_results: int = 3) -> List[Dict[str, Any]]:
        """Get context from similar historical findings.
        
        Args:
            finding: Finding to get context for
            max_results: Maximum number of results
            
        Returns:
            List of similar findings with context
        """
        try:
            similar_findings = self.vector_store.search_similar_findings(
                finding=finding,
                n_results=max_results
            )
            
            logger.debug("Retrieved similar findings context", 
                        finding_id=finding.id, similar_count=len(similar_findings))
            
            return similar_findings
            
        except Exception as e:
            logger.error("Failed to get similar findings context", 
                        finding_id=finding.id, error=str(e))
            return []
            
    def get_triage_context(self, finding: Finding) -> Dict[str, Any]:
        """Get comprehensive context for finding triage.
        
        Args:
            finding: Finding to get triage context for
            
        Returns:
            Dictionary with triage context including techniques and similar findings
        """
        try:
            context = {
                "relevant_techniques": self.get_relevant_techniques(finding),
                "similar_findings": self.get_similar_findings_context(finding),
                "insights": self._get_relevant_insights(finding)
            }
            
            logger.debug("Retrieved triage context", 
                        finding_id=finding.id,
                        techniques_count=len(context["relevant_techniques"]),
                        similar_count=len(context["similar_findings"]),
                        insights_count=len(context["insights"]))
            
            return context
            
        except Exception as e:
            logger.error("Failed to get triage context", 
                        finding_id=finding.id, error=str(e))
            return {"relevant_techniques": [], "similar_findings": [], "insights": []}
            
    async def store_engagement_insights(self, engagement_report: EngagementReport) -> str:
        """Store insights from a completed engagement.
        
        Args:
            engagement_report: Completed engagement report
            
        Returns:
            ID of the stored insight
        """
        try:
            # Generate insights using the security agent
            insights = await self.security_agent.generate_engagement_insights(engagement_report)
            
            # Prepare insight text (insights is a string, not a dict)
            insight_text = f"""
            Engagement Insights for {engagement_report.scope.name}
            
            {insights}
            """
            
            # Prepare metadata
            metadata = {
                "engagement_id": engagement_report.engagement_id,
                "target_scope": engagement_report.scope.name,
                "total_findings": len(engagement_report.findings),
                "high_severity_findings": len([
                    f for f in engagement_report.findings 
                    if f.severity in ["high", "critical"]
                ]),
                "engagement_date": engagement_report.generated_at.isoformat(),
                "tools_used": list(set(f.tool for f in engagement_report.findings))
            }
            
            # Store in vector store
            insight_id = self.vector_store.add_insight(insight_text, metadata)
            
            steps_logger.log_step(
                "knowledge_base",
                f"Stored engagement insights",
                "completed",
                f"Engagement: {engagement_report.scope.name}"
            )
            
            logger.info("Engagement insights stored", 
                       engagement_id=engagement_report.engagement_id,
                       insight_id=insight_id)
            
            return insight_id
            
        except Exception as e:
            logger.error("Failed to store engagement insights", 
                        engagement_id=engagement_report.engagement_id, error=str(e))
            raise
            
    def get_knowledge_stats(self) -> Dict[str, Any]:
        """Get statistics about the knowledge base.
        
        Returns:
            Dictionary with knowledge base statistics
        """
        try:
            stats = self.vector_store.get_collection_stats()
            
            # Add additional stats
            stats["total_entries"] = sum(stats.values())
            stats["last_updated"] = datetime.now().isoformat()
            
            return stats
            
        except Exception as e:
            logger.error("Failed to get knowledge stats", error=str(e))
            return {}
            
    def _store_raw_report(self, content: str, source: str, 
                         report_type: str) -> Optional[str]:
        """Store raw report content for reference.
        
        Args:
            content: Raw report content
            source: Source of the report
            report_type: Type of report
            
        Returns:
            ID of the stored entry or None if failed
        """
        try:
            # Create chunks for large reports
            chunks = self.text_splitter.split_text(content)
            
            # Store the first chunk as the main entry
            if chunks:
                entry = KnowledgeEntry(
                    id=str(uuid.uuid4()),
                    title=f"Raw Report: {Path(source).name}",
                    content=chunks[0],
                    category="raw_report",
                    source=source,
                    tags=[report_type, "raw_content"],
                    effectiveness_score=1.0
                )
                
                return self.vector_store.add_knowledge_entry(entry)
                
        except Exception as e:
            logger.warning("Failed to store raw report", source=source, error=str(e))
            
        return None
        
    def _determine_report_type(self, file_path: Path) -> str:
        """Determine report type from file extension and name.
        
        Args:
            file_path: Path to the report file
            
        Returns:
            Report type string
        """
        extension = file_path.suffix.lower()
        name = file_path.name.lower()
        
        if extension in ['.md', '.markdown']:
            return "markdown_report"
        elif extension in ['.txt']:
            return "text_report"
        elif extension in ['.html', '.htm']:
            return "html_report"
        elif extension in ['.pdf']:
            return "pdf_report"
        elif extension in ['.json']:
            return "json_report"
        elif 'pentest' in name or 'penetration' in name:
            return "pentest_report"
        elif 'vuln' in name or 'vulnerability' in name:
            return "vulnerability_report"
        elif 'bug' in name or 'bounty' in name:
            return "bug_bounty_report"
        else:
            return "manual_report"
            
    def _get_relevant_insights(self, finding: Finding, 
                              max_results: int = 2) -> List[Dict[str, Any]]:
        """Get relevant insights for a finding.
        
        Args:
            finding: Finding to get insights for
            max_results: Maximum number of results
            
        Returns:
            List of relevant insights
        """
        try:
            # Create search query
            query = f"{finding.title} {finding.severity} {finding.tool}"
            
            # Search insights
            insights = self.vector_store.search_insights(
                query=query,
                n_results=max_results
            )
            
            return insights
            
        except Exception as e:
            logger.error("Failed to get relevant insights", 
                        finding_id=finding.id, error=str(e))
            return []


# Global knowledge base instance
_knowledge_base: Optional[KnowledgeBase] = None


def get_knowledge_base(security_agent: SecurityAgent) -> KnowledgeBase:
    """Get the global knowledge base instance.
    
    Args:
        security_agent: SecurityAgent instance
        
    Returns:
        KnowledgeBase instance
    """
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = KnowledgeBase(security_agent)
    return _knowledge_base


def reset_knowledge_base():
    """Reset the global knowledge base instance (for testing)."""
    global _knowledge_base
    _knowledge_base = None