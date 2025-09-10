"""Vector store implementation using Chroma for knowledge base."""

import json
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions

from schemas import KnowledgeEntry, Finding, EngagementReport
from utils.logging import get_logger, steps_logger
from config import settings

logger = get_logger(__name__)


class VectorStore:
    """Vector store for storing and retrieving knowledge base entries."""
    
    def __init__(self, persist_directory: Optional[Path] = None):
        """Initialize the vector store.
        
        Args:
            persist_directory: Directory to persist the vector database
        """
        self.persist_directory = persist_directory or Path(settings.CHROMA_DB_PATH)
        self.persist_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize Chroma client
        self.client = chromadb.PersistentClient(
            path=str(self.persist_directory),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Use default embedding function (sentence transformers)
        self.embedding_function = embedding_functions.DefaultEmbeddingFunction()
        
        # Initialize collections
        self._init_collections()
        
        logger.info("Vector store initialized", 
                   persist_directory=str(self.persist_directory))
        
    def _init_collections(self):
        """Initialize Chroma collections."""
        try:
            # Knowledge base collection for reports, techniques, payloads
            self.knowledge_collection = self.client.get_or_create_collection(
                name="knowledge_base",
                embedding_function=self.embedding_function,
                metadata={"description": "Security knowledge base with reports and techniques"}
            )
            
            # Findings collection for historical findings and patterns
            self.findings_collection = self.client.get_or_create_collection(
                name="findings",
                embedding_function=self.embedding_function,
                metadata={"description": "Historical security findings and patterns"}
            )
            
            # Insights collection for engagement learnings
            self.insights_collection = self.client.get_or_create_collection(
                name="insights",
                embedding_function=self.embedding_function,
                metadata={"description": "Engagement insights and lessons learned"}
            )
            
            logger.info("Vector store collections initialized")
            
        except Exception as e:
            logger.error("Failed to initialize collections", error=str(e))
            raise
            
    def add_knowledge_entry(self, entry: KnowledgeEntry) -> str:
        """Add a knowledge entry to the vector store.
        
        Args:
            entry: KnowledgeEntry to add
            
        Returns:
            ID of the added entry
        """
        try:
            # Generate unique ID
            entry_id = str(uuid.uuid4())
            
            # Prepare document text for embedding
            document_text = self._prepare_knowledge_text(entry)
            
            # Prepare metadata
            metadata = {
                "category": entry.category,
                "source": entry.source or "",
                "created_at": entry.created_at.isoformat(),
                "tags": json.dumps(entry.tags) if entry.tags else "[]",
                "effectiveness_score": entry.effectiveness_score or 0.5,
                "title": entry.title[:100] if entry.title else ""  # Truncate for metadata
            }
            
            # Add to collection
            self.knowledge_collection.add(
                documents=[document_text],
                metadatas=[metadata],
                ids=[entry_id]
            )
            
            steps_logger.log_step(
                "knowledge_base",
                f"Added knowledge entry: {entry.title}",
                "completed",
                f"Category: {entry.category}, Source: {entry.source}"
            )
            
            logger.info("Knowledge entry added", 
                       entry_id=entry_id,
                       category=entry.category,
                       title=entry.title)
            
            return entry_id
            
        except Exception as e:
            logger.error("Failed to add knowledge entry", 
                        title=entry.title, error=str(e))
            raise
            
    def add_finding(self, finding: Finding) -> str:
        """Add a finding to the vector store.
        
        Args:
            finding: Finding to add
            
        Returns:
            ID of the added finding
        """
        try:
            # Prepare document text
            document_text = self._prepare_finding_text(finding)
            
            # Prepare metadata
            metadata = {
                "title": finding.title[:100],
                "severity": finding.severity,
                "target": finding.target or "",
                "tool": finding.tool,
                "status": finding.status,
                "created_at": finding.created_at.isoformat(),
                "cve_id": finding.cve_id or "",
                "confidence": finding.confidence
            }
            
            # Add to collection
            self.findings_collection.add(
                documents=[document_text],
                metadatas=[metadata],
                ids=[finding.id]
            )
            
            logger.debug("Finding added to vector store", 
                        finding_id=finding.id,
                        title=finding.title)
            
            return finding.id
            
        except Exception as e:
            logger.error("Failed to add finding", 
                        finding_id=finding.id, error=str(e))
            raise
            
    def add_insight(self, insight_text: str, metadata: Dict[str, Any]) -> str:
        """Add an engagement insight to the vector store.
        
        Args:
            insight_text: The insight content
            metadata: Additional metadata
            
        Returns:
            ID of the added insight
        """
        try:
            insight_id = str(uuid.uuid4())
            
            # Ensure metadata has required fields
            insight_metadata = {
                "created_at": datetime.now().isoformat(),
                "type": "engagement_insight",
                **metadata
            }
            
            self.insights_collection.add(
                documents=[insight_text],
                metadatas=[insight_metadata],
                ids=[insight_id]
            )
            
            logger.info("Insight added", insight_id=insight_id)
            return insight_id
            
        except Exception as e:
            logger.error("Failed to add insight", error=str(e))
            raise
            
    def search_knowledge(self, query: str, n_results: int = 5, 
                        filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Search the knowledge base.
        
        Args:
            query: Search query
            n_results: Number of results to return
            filters: Optional metadata filters
            
        Returns:
            List of search results with documents and metadata
        """
        try:
            # Build where clause for filtering
            where_clause = None
            if filters:
                where_clause = {}
                for key, value in filters.items():
                    if key in ["category", "source"]:
                        where_clause[key] = value
                        
            results = self.knowledge_collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where_clause
            )
            
            # Format results
            formatted_results = []
            if results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    result = {
                        "document": doc,
                        "metadata": results['metadatas'][0][i] if results['metadatas'] else {},
                        "distance": results['distances'][0][i] if results['distances'] else 0.0,
                        "id": results['ids'][0][i] if results['ids'] else None
                    }
                    formatted_results.append(result)
                    
            logger.debug("Knowledge search completed", 
                        query=query, results_count=len(formatted_results))
            
            return formatted_results
            
        except Exception as e:
            logger.error("Knowledge search failed", query=query, error=str(e))
            return []
            
    def search_similar_findings(self, finding: Finding, n_results: int = 5) -> List[Dict[str, Any]]:
        """Search for similar findings.
        
        Args:
            finding: Finding to find similar ones for
            n_results: Number of results to return
            
        Returns:
            List of similar findings
        """
        try:
            query_text = self._prepare_finding_text(finding)
            
            results = self.findings_collection.query(
                query_texts=[query_text],
                n_results=n_results + 1,  # +1 to exclude self if present
                where={"severity": finding.severity}  # Filter by same severity
            )
            
            # Format and filter results (exclude self)
            formatted_results = []
            if results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    result_id = results['ids'][0][i] if results['ids'] else None
                    if result_id != finding.id:  # Exclude self
                        result = {
                            "document": doc,
                            "metadata": results['metadatas'][0][i] if results['metadatas'] else {},
                            "distance": results['distances'][0][i] if results['distances'] else 0.0,
                            "id": result_id
                        }
                        formatted_results.append(result)
                        
            return formatted_results[:n_results]
            
        except Exception as e:
            logger.error("Similar findings search failed", 
                        finding_id=finding.id, error=str(e))
            return []
            
    def search_insights(self, query: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """Search engagement insights.
        
        Args:
            query: Search query
            n_results: Number of results to return
            
        Returns:
            List of relevant insights
        """
        try:
            results = self.insights_collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            formatted_results = []
            if results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    result = {
                        "document": doc,
                        "metadata": results['metadatas'][0][i] if results['metadatas'] else {},
                        "distance": results['distances'][0][i] if results['distances'] else 0.0,
                        "id": results['ids'][0][i] if results['ids'] else None
                    }
                    formatted_results.append(result)
                    
            return formatted_results
            
        except Exception as e:
            logger.error("Insights search failed", query=query, error=str(e))
            return []
            
    def get_collection_stats(self) -> Dict[str, int]:
        """Get statistics about the vector store collections.
        
        Returns:
            Dictionary with collection counts
        """
        try:
            stats = {
                "knowledge_entries": self.knowledge_collection.count(),
                "findings": self.findings_collection.count(),
                "insights": self.insights_collection.count()
            }
            
            logger.debug("Vector store stats", **stats)
            return stats
            
        except Exception as e:
            logger.error("Failed to get collection stats", error=str(e))
            return {"knowledge_entries": 0, "findings": 0, "insights": 0}
            
    def delete_entry(self, collection_name: str, entry_id: str) -> bool:
        """Delete an entry from a collection.
        
        Args:
            collection_name: Name of the collection
            entry_id: ID of the entry to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            collection_map = {
                "knowledge": self.knowledge_collection,
                "findings": self.findings_collection,
                "insights": self.insights_collection
            }
            
            collection = collection_map.get(collection_name)
            if not collection:
                logger.error("Invalid collection name", collection=collection_name)
                return False
                
            collection.delete(ids=[entry_id])
            logger.info("Entry deleted", collection=collection_name, entry_id=entry_id)
            return True
            
        except Exception as e:
            logger.error("Failed to delete entry", 
                        collection=collection_name, entry_id=entry_id, error=str(e))
            return False
            
    def reset_collections(self) -> bool:
        """Reset all collections (for testing/development).
        
        Returns:
            True if successful, False otherwise
        """
        try:
            self.client.reset()
            self._init_collections()
            logger.warning("Vector store collections reset")
            return True
            
        except Exception as e:
            logger.error("Failed to reset collections", error=str(e))
            return False
            
    def _prepare_knowledge_text(self, entry: KnowledgeEntry) -> str:
        """Prepare knowledge entry text for embedding.
        
        Args:
            entry: KnowledgeEntry to prepare
            
        Returns:
            Formatted text for embedding
        """
        text_parts = []
        
        if entry.title:
            text_parts.append(f"Title: {entry.title}")
            
        if entry.content:
            text_parts.append(f"Content: {entry.content}")
            
        if entry.category:
            text_parts.append(f"Category: {entry.category}")
            
        if entry.tags:
            text_parts.append(f"Tags: {', '.join(entry.tags)}")
            
        return "\n\n".join(text_parts)
        
    def _prepare_finding_text(self, finding: Finding) -> str:
        """Prepare finding text for embedding.
        
        Args:
            finding: Finding to prepare
            
        Returns:
            Formatted text for embedding
        """
        text_parts = []
        
        text_parts.append(f"Title: {finding.title}")
        text_parts.append(f"Description: {finding.description}")
        text_parts.append(f"Severity: {finding.severity}")
        text_parts.append(f"Tool: {finding.tool}")
        
        if finding.target:
            text_parts.append(f"Target: {finding.target}")
            
        if finding.cve_id:
            text_parts.append(f"CVE: {finding.cve_id}")
            
        if finding.remediation:
            text_parts.append(f"Remediation: {finding.remediation}")
            
        if finding.references:
            text_parts.append(f"References: {', '.join(finding.references)}")
            
        return "\n\n".join(text_parts)


# Global vector store instance
_vector_store: Optional[VectorStore] = None


def get_vector_store() -> VectorStore:
    """Get the global vector store instance.
    
    Returns:
        VectorStore instance
    """
    global _vector_store
    if _vector_store is None:
        _vector_store = VectorStore()
    return _vector_store


def reset_vector_store():
    """Reset the global vector store instance (for testing)."""
    global _vector_store
    if _vector_store:
        _vector_store.reset_collections()
    _vector_store = None