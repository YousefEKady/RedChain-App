"""Security agent using LangChain and Google Gemini for red team automation."""

from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.schema import BaseMessage, HumanMessage, SystemMessage
from langchain.tools import BaseTool
from langchain_google_genai import ChatGoogleGenerativeAI

from config import settings
from schemas import Finding, FindingStatus, SeverityLevel, KnowledgeEntry
from utils.logging import get_logger, steps_logger

logger = get_logger(__name__)


class SecurityAgent:
    """Senior cyber security engineer agent for red team automation."""
    
    def __init__(self):
        self.llm = self._initialize_llm()
        self.system_prompt = self._create_system_prompt()
        self.knowledge_base: List[KnowledgeEntry] = []
        
    def _initialize_llm(self) -> ChatGoogleGenerativeAI:
        """Initialize Google Gemini LLM."""
        try:
            llm = ChatGoogleGenerativeAI(
                model=settings.gemini_model,
                google_api_key=settings.google_api_key,
                temperature=settings.model_temperature,
                max_tokens=settings.max_tokens,
                convert_system_message_to_human=True
            )
            
            steps_logger.log_step(
                "initialization",
                "LLM initialization",
                "completed",
                f"Initialized {settings.gemini_model} with temperature {settings.model_temperature}"
            )
            
            logger.info("LLM initialized successfully", 
                       model=settings.gemini_model,
                       temperature=settings.model_temperature)
            
            return llm
            
        except Exception as e:
            steps_logger.log_step(
                "initialization",
                "LLM initialization",
                "failed",
                f"Failed to initialize LLM: {str(e)}"
            )
            logger.error("Failed to initialize LLM", error=str(e))
            raise
            
    def _create_system_prompt(self) -> str:
        """Create system prompt for the security agent."""
        return """
You are a senior cyber security engineer with extensive experience in:
- Bug hunting and vulnerability research
- Penetration testing and red team operations
- Security tool analysis and triage
- Threat intelligence and attack methodologies

Your role in this red team automation framework:

1. **Finding Triage**: Analyze security findings from automated tools (subfinder, httpx, nuclei, Burp Suite) and determine if they are true positives or false positives. Consider:
   - Technical accuracy of the finding
   - Exploitability and impact
   - Context of the target environment
   - Common false positive patterns

2. **Knowledge Extraction**: When provided with security reports or write-ups, extract:
   - Attack techniques and methodologies
   - Effective payloads and exploitation methods
   - Tool configurations and parameters
   - Lessons learned and insights

3. **Remediation Advice**: Provide actionable remediation recommendations for confirmed vulnerabilities, including:
   - Specific configuration changes
   - Code fixes where applicable
   - Compensating controls
   - Priority and timeline suggestions

4. **Continuous Learning**: After each engagement, analyze what worked well and what didn't, storing insights for future improvements.

Always provide:
- Clear reasoning for your decisions
- Confidence scores (0.0-1.0) for your assessments
- Specific technical details
- References to relevant standards (OWASP, CWE, CVE)

Be thorough but concise. Focus on actionable intelligence.
"""

    async def triage_finding(self, finding: Finding, context: Optional[str] = None) -> Dict[str, Any]:
        """Triage a security finding to determine if it's a true or false positive.
        
        Args:
            finding: The finding to analyze
            context: Additional context about the target or environment
            
        Returns:
            Dictionary with triage results including status, confidence, and reasoning
        """
        # Input validation
        if not finding:
            raise ValueError("Finding cannot be None")
        
        if not finding.title or not finding.description:
            logger.warning("Finding missing required fields", finding_id=getattr(finding, 'id', 'unknown'))
            return {
                'status': FindingStatus.NEEDS_REVIEW,
                'confidence': 0.0,
                'reasoning': 'Finding missing required title or description',
                'remediation': '',
                'references': []
            }
        
        steps_logger.log_step(
            "triage",
            f"Starting triage for finding: {finding.title}",
            "started",
            f"Target: {finding.target} | Tool: {finding.tool} | Severity: {finding.severity}"
        )
        
        try:
            # Prepare the triage prompt
            triage_prompt = self._create_triage_prompt(finding, context)
            
            # Get relevant knowledge from KB
            relevant_knowledge = self._get_relevant_knowledge(finding)
            
            # Create messages for the LLM
            messages = [
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=triage_prompt)
            ]
            
            if relevant_knowledge:
                kb_context = "\n\n".join([f"Knowledge: {k.title}\n{k.content}" for k in relevant_knowledge[:3]])
                messages.append(HumanMessage(content=f"Relevant knowledge from previous engagements:\n{kb_context}"))
            
            # Get LLM response
            response = await self.llm.ainvoke(messages)
            
            # Parse the response
            triage_result = self._parse_triage_response(response.content, finding)
            
            steps_logger.log_triage_result(
                finding.id,
                triage_result['status'],
                triage_result['confidence']
            )
            
            logger.info("Finding triage completed",
                       finding_id=finding.id,
                       status=triage_result['status'],
                       confidence=triage_result['confidence'])
            
            return triage_result
            
        except Exception as e:
            steps_logger.log_step(
                "triage",
                f"Triage failed for finding: {finding.title}",
                "failed",
                f"Error: {str(e)}"
            )
            logger.error("Triage failed", finding_id=finding.id, error=str(e))
            raise
            
    def _create_triage_prompt(self, finding: Finding, context: Optional[str] = None) -> str:
        """Create a detailed triage prompt for the finding."""
        prompt = f"""
Please analyze the following security finding and determine if it's a true positive or false positive:

**Finding Details:**
- Title: {finding.title}
- Description: {finding.description}
- Severity: {finding.severity}
- Target: {finding.target}
- URL: {finding.url or 'N/A'}
- Tool: {finding.tool}
- CVE ID: {finding.cve_id or 'N/A'}
- CVSS Score: {finding.cvss_score or 'N/A'}

**Raw Tool Output:**
{finding.raw_output or 'No raw output available'}

**Additional Context:**
{context or 'No additional context provided'}

**Please provide your analysis in the following format:**

STATUS: [TRUE_POSITIVE|FALSE_POSITIVE]
CONFIDENCE: [0.0-1.0]
REASONING: [Detailed explanation of your decision]
REMEDIATION: [Specific remediation steps if true positive]
REFERENCES: [Relevant CVE, CWE, or OWASP references]

Consider:
1. Technical accuracy of the finding
2. Exploitability and real-world impact
3. Common false positive patterns for this tool
4. Context of the target environment
5. Severity appropriateness
"""
        return prompt
        
    def _parse_triage_response(self, response: str, finding: Finding) -> Dict[str, Any]:
        """Parse the LLM triage response into structured data with improved error handling."""
        if not response or not response.strip():
            logger.warning("Empty response received for triage", finding_id=finding.id)
            return {
                'status': FindingStatus.NEEDS_REVIEW,
                'confidence': 0.0,
                'reasoning': 'Empty response from LLM',
                'remediation': '',
                'references': []
            }
        
        lines = response.strip().split('\n')
        result = {
            'status': FindingStatus.NEEDS_REVIEW,
            'confidence': 0.5,
            'reasoning': '',
            'remediation': '',
            'references': []
        }
        
        try:
            for line in lines:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                    
                key, value = line.split(':', 1)
                key = key.strip().upper()
                value = value.strip()
                
                if key == 'STATUS':
                    status_text = value.upper()
                    if 'TRUE_POSITIVE' in status_text or 'TRUE POSITIVE' in status_text:
                        result['status'] = FindingStatus.TRUE_POSITIVE
                    elif 'FALSE_POSITIVE' in status_text or 'FALSE POSITIVE' in status_text:
                        result['status'] = FindingStatus.FALSE_POSITIVE
                        
                elif key == 'CONFIDENCE':
                    try:
                        confidence = float(value)
                        # Clamp confidence between 0.0 and 1.0
                        result['confidence'] = max(0.0, min(1.0, confidence))
                    except (ValueError, TypeError) as e:
                        logger.warning("Invalid confidence value", value=value, error=str(e))
                        
                elif key == 'REASONING':
                    result['reasoning'] = value
                    
                elif key == 'REMEDIATION':
                    result['remediation'] = value
                    
                elif key == 'REFERENCES':
                    if value:
                        result['references'] = [ref.strip() for ref in value.split(',') if ref.strip()]
        
        except Exception as e:
            logger.error("Error parsing triage response", error=str(e), response_preview=response[:200])
            result['reasoning'] = f"Error parsing LLM response: {str(e)}"
            result['confidence'] = 0.0
        
        return result
        
    def _get_relevant_knowledge(self, finding: Finding) -> List[KnowledgeEntry]:
        """Get relevant knowledge entries for the finding using improved matching."""
        if not self.knowledge_base:
            return []
        
        # Extract meaningful keywords, filtering out common words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were'}
        
        keywords = set()
        # Add title words
        if finding.title:
            title_words = [word.lower().strip() for word in finding.title.split() if len(word) > 2 and word.lower() not in stop_words]
            keywords.update(title_words)
        
        # Add tool name
        if finding.tool:
            tool_value = finding.tool.value if hasattr(finding.tool, 'value') else str(finding.tool)
            keywords.add(tool_value.lower())
        
        # Add severity
        if finding.severity:
            severity_value = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            keywords.add(severity_value.lower())
        
        # Add description keywords (first 10 meaningful words)
        if finding.description:
            desc_words = [word.lower().strip() for word in finding.description.split()[:20] 
                         if len(word) > 3 and word.lower() not in stop_words]
            keywords.update(desc_words[:10])
        
        if not keywords:
            return []
        
        # Score entries based on keyword matches and effectiveness
        scored_entries = []
        for entry in self.knowledge_base:
            entry_text = f"{entry.title} {entry.content}".lower()
            
            # Calculate keyword match score
            keyword_score = sum(1 for keyword in keywords if keyword in entry_text)
            
            # Weight by effectiveness score
            effectiveness = entry.effectiveness_score or 0.5
            final_score = keyword_score * effectiveness
            
            if keyword_score > 0:
                scored_entries.append((entry, final_score))
        
        # Sort by score and return top matches
        scored_entries.sort(key=lambda x: x[1], reverse=True)
        return [entry for entry, _ in scored_entries[:5]]  # Return top 5 matches
        
    async def extract_knowledge_from_report(self, report_content: str, source: str) -> List[KnowledgeEntry]:
        """Extract techniques, payloads, and methodologies from a security report.
        
        Args:
            report_content: The content of the security report
            source: Source of the report (for attribution)
            
        Returns:
            List of extracted knowledge entries
        """
        # Input validation
        if not report_content or not report_content.strip():
            logger.warning("Empty report content provided for knowledge extraction", source=source)
            return []
        
        if not source or not source.strip():
            source = "unknown_source"
        
        # Limit content size to prevent excessive processing
        max_content_length = 50000  # 50KB limit
        if len(report_content) > max_content_length:
            logger.info("Truncating large report content", original_length=len(report_content), max_length=max_content_length)
            report_content = report_content[:max_content_length] + "\n[Content truncated due to size limit]"
        
        steps_logger.log_step(
            "knowledge_extraction",
            f"Extracting knowledge from report: {source}",
            "started"
        )
        
        try:
            extraction_prompt = f"""
Analyze the following security report and extract actionable knowledge:

{report_content}

Please extract and categorize the following information:

1. **TECHNIQUES**: Attack techniques and methodologies used
2. **PAYLOADS**: Specific payloads, commands, or exploits
3. **TOOLS**: Tools and configurations mentioned
4. **INSIGHTS**: Lessons learned and key insights

For each item, provide:
- Title: Brief descriptive title
- Category: technique/payload/tool/insight
- Content: Detailed description
- Tags: Relevant tags for categorization
- Effectiveness: Score from 0.0-1.0 based on how effective/useful this knowledge appears

Format each entry as:
ENTRY_START
Title: [title]
Category: [category]
Content: [detailed content]
Tags: [tag1, tag2, tag3]
Effectiveness: [0.0-1.0]
ENTRY_END
"""
            
            messages = [
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=extraction_prompt)
            ]
            
            response = await self.llm.ainvoke(messages)
            
            # Parse extracted knowledge
            knowledge_entries = self._parse_knowledge_extraction(response.content, source)
            
            # Add to knowledge base
            self.knowledge_base.extend(knowledge_entries)
            
            steps_logger.log_step(
                "knowledge_extraction",
                f"Knowledge extraction completed",
                "completed",
                f"Extracted {len(knowledge_entries)} knowledge entries from {source}"
            )
            
            logger.info("Knowledge extraction completed",
                       source=source,
                       entries_extracted=len(knowledge_entries))
            
            return knowledge_entries
            
        except Exception as e:
            steps_logger.log_step(
                "knowledge_extraction",
                f"Knowledge extraction failed",
                "failed",
                f"Error: {str(e)}"
            )
            logger.error("Knowledge extraction failed", source=source, error=str(e))
            raise
            
    def _parse_knowledge_extraction(self, response: str, source: str) -> List[KnowledgeEntry]:
        """Parse knowledge extraction response into KnowledgeEntry objects with improved validation."""
        if not response or not response.strip():
            logger.warning("Empty response for knowledge extraction", source=source)
            return []
        
        entries = []
        current_entry = {}
        
        try:
            lines = response.split('\n')
            in_entry = False
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                if line == 'ENTRY_START':
                    in_entry = True
                    current_entry = {}
                    continue
                elif line == 'ENTRY_END':
                    if in_entry and current_entry:
                        # Validate required fields
                        title = current_entry.get('title', '').strip()
                        content = current_entry.get('content', '').strip()
                        
                        if not title or not content:
                            logger.warning("Skipping knowledge entry with missing title or content", 
                                         line_num=line_num, title=title[:50] if title else "None")
                            current_entry = {}
                            in_entry = False
                            continue
                        
                        try:
                            # Validate and clamp effectiveness score
                            effectiveness = current_entry.get('effectiveness', 0.5)
                            if not isinstance(effectiveness, (int, float)) or effectiveness < 0 or effectiveness > 1:
                                effectiveness = 0.5
                            
                            entry = KnowledgeEntry(
                                id=str(uuid.uuid4()),
                                title=title[:200],  # Limit title length
                                content=content[:5000],  # Limit content length
                                category=current_entry.get('category', 'general').lower(),
                                tags=[tag.strip()[:50] for tag in current_entry.get('tags', []) if tag.strip()][:10],  # Limit tags
                                source=source,
                                effectiveness_score=effectiveness
                            )
                            entries.append(entry)
                        except Exception as e:
                            logger.warning("Failed to create knowledge entry", error=str(e), line_num=line_num)
                    
                    current_entry = {}
                    in_entry = False
                    continue
                    
                if in_entry and ':' in line:
                    try:
                        key, value = line.split(':', 1)
                        key = key.strip().lower()
                        value = value.strip()
                        
                        if key == 'title':
                            current_entry['title'] = value
                        elif key == 'category':
                            current_entry['category'] = value
                        elif key == 'content':
                            current_entry['content'] = value
                        elif key == 'tags':
                            if value:
                                current_entry['tags'] = [tag.strip() for tag in value.split(',') if tag.strip()]
                            else:
                                current_entry['tags'] = []
                        elif key == 'effectiveness':
                            try:
                                effectiveness = float(value)
                                current_entry['effectiveness'] = max(0.0, min(1.0, effectiveness))
                            except (ValueError, TypeError):
                                logger.warning("Invalid effectiveness score", value=value, line_num=line_num)
                                current_entry['effectiveness'] = 0.5
                    except Exception as e:
                        logger.warning("Error parsing knowledge entry line", error=str(e), line=line[:100], line_num=line_num)
                        
        except Exception as e:
            logger.error("Error parsing knowledge extraction response", error=str(e), source=source)
            
        logger.info("Knowledge extraction parsing completed", entries_parsed=len(entries), source=source)
        return entries
        
    async def generate_insights(self, engagement_summary: Dict[str, Any]) -> str:
        """Generate insights and lessons learned from an engagement.
        
        Args:
            engagement_summary: Summary of the engagement results
            
        Returns:
            Generated insights and recommendations for future engagements
        """
        steps_logger.log_step(
            "analysis",
            "Generating engagement insights",
            "started"
        )
        
        try:
            insights_prompt = f"""
Analyze the following red team engagement results and provide insights for future improvements:

**Engagement Summary:**
{engagement_summary}

**Please provide:**

1. **WHAT WORKED WELL**: Techniques, tools, and approaches that were effective
2. **AREAS FOR IMPROVEMENT**: What could be done better next time
3. **TOOL EFFECTIVENESS**: Analysis of tool performance and accuracy
4. **FALSE POSITIVE PATTERNS**: Common false positive patterns observed
5. **RECOMMENDATIONS**: Specific recommendations for future engagements
6. **KNOWLEDGE GAPS**: Areas where additional knowledge or tools would be beneficial

Provide actionable insights that can improve future red team operations.
"""
            
            messages = [
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=insights_prompt)
            ]
            
            response = await self.llm.ainvoke(messages)
            
            steps_logger.log_step(
                "analysis",
                "Engagement insights generated",
                "completed"
            )
            
            logger.info("Engagement insights generated successfully")
            
            return response.content
            
        except Exception as e:
            steps_logger.log_step(
                "analysis",
                "Insights generation failed",
                "failed",
                f"Error: {str(e)}"
            )
            logger.error("Insights generation failed", error=str(e))
            raise
            
    async def batch_analyze_findings(self, findings: List[Finding]) -> Dict[str, Any]:
        """Analyze multiple findings in batch for efficiency and pattern detection.
        
        Args:
            findings: List of findings to analyze
            
        Returns:
            Dictionary containing batch analysis results
        """
        steps_logger.log_step(
            "batch_analysis",
            f"Starting batch analysis of {len(findings)} findings",
            "started"
        )
        
        try:
            # Group findings by type and severity for pattern analysis
            grouped_findings = self._group_findings_for_analysis(findings)
            
            # Analyze each group
            analysis_results = {
                "total_findings": len(findings),
                "groups_analyzed": len(grouped_findings),
                "patterns_detected": [],
                "high_confidence_findings": [],
                "potential_false_positives": [],
                "recommendations": []
            }
            
            for group_key, group_findings in grouped_findings.items():
                group_analysis = await self._analyze_finding_group(group_key, group_findings)
                
                # Merge results
                analysis_results["patterns_detected"].extend(group_analysis.get("patterns", []))
                analysis_results["high_confidence_findings"].extend(group_analysis.get("high_confidence", []))
                analysis_results["potential_false_positives"].extend(group_analysis.get("false_positives", []))
                analysis_results["recommendations"].extend(group_analysis.get("recommendations", []))
            
            # Generate overall insights
            overall_insights = await self._generate_batch_insights(findings, analysis_results)
            analysis_results["insights"] = overall_insights
            
            steps_logger.log_step(
                "batch_analysis",
                "Batch analysis completed",
                "completed",
                f"Analyzed {len(findings)} findings, detected {len(analysis_results['patterns_detected'])} patterns"
            )
            
            logger.info("Batch analysis completed",
                       findings_count=len(findings),
                       patterns_detected=len(analysis_results["patterns_detected"]))
            
            return analysis_results
            
        except Exception as e:
            steps_logger.log_step(
                "batch_analysis",
                "Batch analysis failed",
                "failed",
                f"Error: {str(e)}"
            )
            logger.error("Batch analysis failed", error=str(e))
            raise
    
    def _group_findings_for_analysis(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by type and characteristics for efficient analysis."""
        groups = {}
        
        for finding in findings:
            # Create group key based on finding tool and severity
            # Handle both enum and string values
            tool_value = finding.tool.value if hasattr(finding.tool, 'value') else str(finding.tool)
            severity_value = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            group_key = f"{tool_value}_{severity_value}"
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(finding)
        
        return groups
    
    async def _analyze_finding_group(self, group_key: str, findings: List[Finding]) -> Dict[str, Any]:
        """Analyze a group of similar findings for patterns and insights."""
        try:
            # Prepare group analysis prompt
            findings_summary = "\n".join([
                f"- {f.title}: {f.description} (Confidence: {f.confidence})" 
                for f in findings[:10]  # Limit to first 10 for prompt size
            ])
            
            group_prompt = f"""
Analyze this group of similar security findings for patterns and insights:

**Group Type:** {group_key}
**Number of Findings:** {len(findings)}

**Sample Findings:**
{findings_summary}

**Analysis Required:**
1. Are these likely true positives or false positives?
2. What patterns do you see across these findings?
3. What is the overall confidence level for this group?
4. Any specific recommendations for this type of finding?

Provide analysis in this format:
CONFIDENCE: [high/medium/low]
PATTERNS: [list of patterns observed]
RECOMMENDATIONS: [specific recommendations]
FALSE_POSITIVE_LIKELIHOOD: [high/medium/low]
"""
            
            messages = [
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=group_prompt)
            ]
            
            response = await self.llm.ainvoke(messages)
            
            # Parse response
            return self._parse_group_analysis(response.content, findings)
            
        except Exception as e:
            logger.warning(f"Group analysis failed for {group_key}", error=str(e))
            return {"patterns": [], "high_confidence": [], "false_positives": [], "recommendations": []}
    
    def _parse_group_analysis(self, response: str, findings: List[Finding]) -> Dict[str, Any]:
        """Parse group analysis response into structured data."""
        result = {
            "patterns": [],
            "high_confidence": [],
            "false_positives": [],
            "recommendations": []
        }
        
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if line.startswith('CONFIDENCE:'):
                confidence = line.split(':', 1)[1].strip().lower()
                if confidence == 'high':
                    result["high_confidence"].extend([f.id for f in findings])
            elif line.startswith('PATTERNS:'):
                patterns = line.split(':', 1)[1].strip()
                if patterns:
                    result["patterns"].append(patterns)
            elif line.startswith('RECOMMENDATIONS:'):
                recommendations = line.split(':', 1)[1].strip()
                if recommendations:
                    result["recommendations"].append(recommendations)
            elif line.startswith('FALSE_POSITIVE_LIKELIHOOD:'):
                likelihood = line.split(':', 1)[1].strip().lower()
                if likelihood in ['high', 'medium']:
                    result["false_positives"].extend([f.id for f in findings])
        
        return result
    
    async def _generate_batch_insights(self, findings: List[Finding], analysis_results: Dict[str, Any]) -> str:
        """Generate overall insights from batch analysis results."""
        try:
            insights_prompt = f"""
Based on the analysis of {len(findings)} security findings, provide strategic insights:

**Analysis Summary:**
- Total findings analyzed: {analysis_results['total_findings']}
- High confidence findings: {len(analysis_results['high_confidence_findings'])}
- Potential false positives: {len(analysis_results['potential_false_positives'])}
- Patterns detected: {len(analysis_results['patterns_detected'])}

**Key Patterns:**
{chr(10).join(analysis_results['patterns_detected'][:5])}

**Provide strategic insights covering:**
1. Overall security posture assessment
2. Priority areas for immediate attention
3. Tool effectiveness and tuning recommendations
4. False positive reduction strategies
5. Next steps for the security team

Keep insights actionable and specific.
"""
            
            messages = [
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=insights_prompt)
            ]
            
            response = await self.llm.ainvoke(messages)
            return response.content
            
        except Exception as e:
            logger.warning("Failed to generate batch insights", error=str(e))
            return "Unable to generate insights due to analysis error."
    
    async def prioritize_findings(self, findings: List[Finding]) -> List[Finding]:
        """Prioritize findings based on AI analysis and risk assessment.
        
        Args:
            findings: List of findings to prioritize
            
        Returns:
            Sorted list of findings by priority (highest first)
        """
        steps_logger.log_step(
            "prioritization",
            f"Prioritizing {len(findings)} findings",
            "started"
        )
        
        try:
            # Calculate priority scores for each finding
            prioritized_findings = []
            
            for finding in findings:
                priority_score = await self._calculate_priority_score(finding)
                finding_copy = finding.model_copy()
                # Add priority score as metadata
                if not hasattr(finding_copy, 'metadata'):
                    finding_copy.metadata = {}
                finding_copy.metadata['priority_score'] = priority_score
                prioritized_findings.append(finding_copy)
            
            # Sort by priority score (highest first)
            prioritized_findings.sort(key=lambda x: x.metadata.get('priority_score', 0), reverse=True)
            
            steps_logger.log_step(
                "prioritization",
                "Finding prioritization completed",
                "completed"
            )
            
            logger.info("Findings prioritized successfully", count=len(findings))
            
            return prioritized_findings
            
        except Exception as e:
            steps_logger.log_step(
                "prioritization",
                "Finding prioritization failed",
                "failed",
                f"Error: {str(e)}"
            )
            logger.error("Finding prioritization failed", error=str(e))
            return findings  # Return original list if prioritization fails
    
    async def _calculate_priority_score(self, finding: Finding) -> float:
        """Calculate priority score for a finding based on multiple factors."""
        try:
            # Base score from severity
            severity_scores = {
                "critical": 1.0,
                "high": 0.8,
                "medium": 0.6,
                "low": 0.4,
                "info": 0.2
            }
            
            base_score = severity_scores.get(finding.severity.lower(), 0.5)
            
            # Adjust based on confidence
            confidence_multiplier = finding.confidence
            
            # Adjust based on exploitability keywords
            exploitability_keywords = [
                "rce", "remote code execution", "sql injection", "xss", 
                "authentication bypass", "privilege escalation", "directory traversal"
            ]
            
            exploitability_bonus = 0.0
            finding_text = f"{finding.title} {finding.description}".lower()
            for keyword in exploitability_keywords:
                if keyword in finding_text:
                    exploitability_bonus += 0.1
            
            # Cap exploitability bonus
            exploitability_bonus = min(exploitability_bonus, 0.3)
            
            # Calculate final score
            priority_score = (base_score * confidence_multiplier) + exploitability_bonus
            
            # Ensure score is between 0 and 1
            return min(max(priority_score, 0.0), 1.0)
            
        except Exception as e:
            logger.warning(f"Failed to calculate priority score for finding {finding.id}", error=str(e))
            return 0.5  # Default medium priority
    
    def get_knowledge_base_summary(self) -> Dict[str, Any]:
        """Get a summary of the current knowledge base."""
        categories = {}
        for entry in self.knowledge_base:
            if entry.category not in categories:
                categories[entry.category] = 0
            categories[entry.category] += 1
            
        return {
            "total_entries": len(self.knowledge_base),
            "categories": categories,
            "latest_entries": [
                {
                    "title": entry.title,
                    "category": entry.category,
                    "source": entry.source,
                    "created_at": entry.created_at.isoformat()
                }
                for entry in sorted(self.knowledge_base, key=lambda x: x.created_at, reverse=True)[:5]
            ]
        }
    
    async def generate_engagement_insights(self, engagement_report) -> str:
        """Generate insights from an engagement report.
        
        Args:
            engagement_report: The engagement report to analyze
            
        Returns:
            Generated insights as a string
        """
        try:
            # Extract key information from the report
            findings_summary = f"Total findings: {len(engagement_report.findings)}"
            if hasattr(engagement_report, 'findings') and engagement_report.findings:
                true_positives = [f for f in engagement_report.findings if f.status.value == "true_positive"]
                false_positives = [f for f in engagement_report.findings if f.status.value == "false_positive"]
                findings_summary += f", True positives: {len(true_positives)}, False positives: {len(false_positives)}"
            
            prompt = f"""
Analyze this red team engagement and provide strategic insights:

**Engagement Summary:**
- Engagement ID: {engagement_report.engagement_id}
- Target: {engagement_report.scope.name if hasattr(engagement_report, 'scope') else 'Unknown'}
- {findings_summary}

**Key Questions:**
1. What are the most critical security gaps identified?
2. What attack patterns were most successful?
3. What defensive improvements should be prioritized?
4. What trends do you see in the security posture?
5. What should be the focus for future engagements?

Provide actionable insights for both red team and blue team perspectives.
"""
            
            messages = [
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=prompt)
            ]
            
            response = await self.llm.ainvoke(messages)
            return response.content
            
        except Exception as e:
            logger.error(f"Failed to generate engagement insights: {e}")
            return f"Failed to generate insights: {str(e)}"