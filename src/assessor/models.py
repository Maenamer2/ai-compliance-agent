"""Data models for the AI compliance assessor."""

from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk level classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class ComplianceStatus(str, Enum):
    """Compliance status."""
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class AISystemType(str, Enum):
    """Types of AI systems."""
    LLM = "llm"
    VISION = "vision"
    MULTIMODAL = "multimodal"
    PREDICTIVE = "predictive"
    GENERATIVE = "generative"
    RECOMMENDATION = "recommendation"
    OTHER = "other"


class AISystemInfo(BaseModel):
    """Information about the AI system being assessed."""
    name: str
    type: AISystemType
    use_case: str
    description: Optional[str] = None
    data_types: List[str] = Field(default_factory=list)
    user_base: Optional[str] = None
    deployment_region: Optional[str] = None
    model_info: Optional[Dict[str, Any]] = None
    architecture: Optional[Dict[str, Any]] = None


class Finding(BaseModel):
    """A single assessment finding."""
    id: str
    category: str
    title: str
    description: str
    severity: RiskLevel
    status: ComplianceStatus
    recommendation: str
    references: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FrameworkAssessment(BaseModel):
    """Assessment results for a specific framework."""
    framework_name: str
    framework_version: str
    overall_status: ComplianceStatus
    score: float = Field(ge=0.0, le=100.0)
    findings: List[Finding] = Field(default_factory=list)
    summary: str


class SecurityAssessment(BaseModel):
    """Security assessment results."""
    category: str
    overall_risk: RiskLevel
    score: float = Field(ge=0.0, le=100.0)
    findings: List[Finding] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class AssessmentResult(BaseModel):
    """Complete assessment results."""
    assessment_id: str
    timestamp: datetime = Field(default_factory=datetime.now)
    system_info: AISystemInfo
    frameworks: List[FrameworkAssessment] = Field(default_factory=list)
    security: List[SecurityAssessment] = Field(default_factory=list)
    overall_score: float = Field(ge=0.0, le=100.0)
    overall_risk: RiskLevel
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0

    def summary(self) -> str:
        """Generate a text summary of the assessment."""
        lines = [
            f"\n{'='*60}",
            f"AI COMPLIANCE & SECURITY ASSESSMENT",
            f"{'='*60}",
            f"System: {self.system_info.name}",
            f"Type: {self.system_info.type.value}",
            f"Assessment ID: {self.assessment_id}",
            f"Timestamp: {self.timestamp.isoformat()}",
            f"\n{'OVERALL RESULTS':-^60}",
            f"Overall Score: {self.overall_score:.1f}/100",
            f"Overall Risk: {self.overall_risk.value.upper()}",
            f"Total Findings: {self.total_findings}",
            f"  Critical: {self.critical_findings}",
            f"  High: {self.high_findings}",
        ]

        if self.frameworks:
            lines.append(f"\n{'COMPLIANCE FRAMEWORKS':-^60}")
            for fw in self.frameworks:
                lines.append(f"  {fw.framework_name}: {fw.overall_status.value} ({fw.score:.1f}/100)")

        if self.security:
            lines.append(f"\n{'SECURITY ASSESSMENTS':-^60}")
            for sec in self.security:
                lines.append(f"  {sec.category}: {sec.overall_risk.value} ({sec.score:.1f}/100)")

        lines.append(f"{'='*60}\n")
        return "\n".join(lines)
