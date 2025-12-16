"""EU AI Act compliance framework."""

from typing import List
from .base import ComplianceFramework
from ..assessor.models import (
    AISystemInfo, FrameworkAssessment, Finding,
    RiskLevel, ComplianceStatus
)


class EUAIActFramework(ComplianceFramework):
    """EU AI Act risk-based compliance assessment."""

    def __init__(self):
        """Initialize EU AI Act framework."""
        super().__init__("EU AI Act", "2024")

    def get_requirements(self) -> List[str]:
        """Get EU AI Act requirements."""
        return [
            "Risk classification",
            "Prohibited AI practices",
            "High-risk AI requirements",
            "Transparency obligations",
            "Data governance",
            "Technical documentation",
            "Record-keeping",
            "Human oversight",
            "Accuracy and robustness",
            "Cybersecurity"
        ]

    def _classify_risk(self, system_info: AISystemInfo) -> str:
        """Classify AI system risk level per EU AI Act."""
        # Prohibited practices
        prohibited_uses = ["social_scoring", "subliminal_manipulation", "exploitation_vulnerabilities"]
        if system_info.use_case in prohibited_uses:
            return "prohibited"

        # High-risk use cases
        high_risk_uses = [
            "biometric", "critical_infrastructure", "education_scoring",
            "employment", "hiring", "credit_scoring", "law_enforcement",
            "migration_control", "justice", "democratic_process"
        ]
        if system_info.use_case in high_risk_uses:
            return "high"

        # Limited risk (transparency obligations)
        if system_info.type.value in ["llm", "generative"]:
            return "limited"

        return "minimal"

    def assess(self, system_info: AISystemInfo) -> FrameworkAssessment:
        """Assess AI system for EU AI Act compliance."""
        findings = []
        risk_class = self._classify_risk(system_info)

        # Check for prohibited practices
        if risk_class == "prohibited":
            findings.append(Finding(
                id="euai-001",
                category="Prohibited Practice",
                title="PROHIBITED AI SYSTEM - Deployment banned",
                description=f"The AI system use case '{system_info.use_case}' is classified as "
                           "a prohibited AI practice under EU AI Act Article 5. This system "
                           "cannot be deployed in the EU.",
                severity=RiskLevel.CRITICAL,
                status=ComplianceStatus.NON_COMPLIANT,
                recommendation="Discontinue this AI system immediately or fundamentally redesign "
                              "to avoid prohibited practices.",
                references=["EU AI Act Article 5"]
            ))

        # High-risk systems
        elif risk_class == "high":
            findings.append(Finding(
                id="euai-002",
                category="High-Risk Classification",
                title="High-risk AI system - Comprehensive requirements apply",
                description="This AI system is classified as high-risk and must comply with "
                           "extensive requirements including risk management, data governance, "
                           "technical documentation, transparency, human oversight, and accuracy.",
                severity=RiskLevel.HIGH,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement full compliance program including: conformity assessment, "
                              "CE marking, registration in EU database, ongoing monitoring",
                references=["EU AI Act Article 6, Annex III"]
            ))

            # Risk management system
            findings.append(Finding(
                id="euai-003",
                category="Risk Management",
                title="Risk management system required",
                description="High-risk AI systems must have a documented risk management system "
                           "throughout the entire lifecycle.",
                severity=RiskLevel.HIGH,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Establish risk management process: 1) Identify known/foreseeable risks, "
                              "2) Estimate and evaluate risks, 3) Implement mitigation measures, "
                              "4) Monitor and update",
                references=["EU AI Act Article 9"]
            ))

            # Data governance
            findings.append(Finding(
                id="euai-004",
                category="Data Governance",
                title="Data governance and quality requirements",
                description="Training, validation, and testing datasets must meet quality criteria.",
                severity=RiskLevel.HIGH,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Relevant, representative, error-free datasets, "
                              "2) Appropriate statistical properties, 3) Data bias examination, "
                              "4) Gap/shortcoming identification",
                references=["EU AI Act Article 10"]
            ))

            # Technical documentation
            findings.append(Finding(
                id="euai-005",
                category="Documentation",
                title="Technical documentation required",
                description="Comprehensive technical documentation must be maintained and kept up-to-date.",
                severity=RiskLevel.MEDIUM,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Document: 1) System description and capabilities, 2) Development process, "
                              "3) Monitoring and control measures, 4) Validation and testing, "
                              "5) Architecture and data requirements",
                references=["EU AI Act Article 11, Annex IV"]
            ))

            # Human oversight
            findings.append(Finding(
                id="euai-006",
                category="Human Oversight",
                title="Human oversight measures required",
                description="High-risk systems must enable effective human oversight.",
                severity=RiskLevel.HIGH,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Human-in-the-loop, human-on-the-loop, or human-in-command, "
                              "2) Ability to override or halt system, 3) Interpretable outputs",
                references=["EU AI Act Article 14"]
            ))

            # Accuracy and robustness
            findings.append(Finding(
                id="euai-007",
                category="Robustness",
                title="Accuracy, robustness, and cybersecurity required",
                description="System must achieve appropriate levels of accuracy and be resilient to errors.",
                severity=RiskLevel.HIGH,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Accuracy metrics and monitoring, 2) Robustness testing, "
                              "3) Cybersecurity measures, 4) Resilience to adversarial attacks",
                references=["EU AI Act Article 15"]
            ))

        # Limited risk (transparency)
        if system_info.type.value in ["llm", "generative"]:
            findings.append(Finding(
                id="euai-008",
                category="Transparency",
                title="AI-generated content disclosure required",
                description="Users must be informed when interacting with AI systems or "
                           "consuming AI-generated content.",
                severity=RiskLevel.MEDIUM,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement clear disclosure: 1) AI system interaction notice, "
                              "2) AI-generated content labeling, 3) Deepfake detection and marking",
                references=["EU AI Act Article 52"]
            ))

        # General purpose AI
        if system_info.type.value == "llm":
            findings.append(Finding(
                id="euai-009",
                category="General Purpose AI",
                title="GPAI transparency requirements",
                description="General purpose AI models must provide technical documentation "
                           "and comply with transparency requirements.",
                severity=RiskLevel.MEDIUM,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Provide: 1) Model card with capabilities and limitations, "
                              "2) Training data information, 3) Energy consumption, "
                              "4) Copyright compliance for training data",
                references=["EU AI Act Article 53"]
            ))

        # Calculate score
        critical_count = sum(1 for f in findings if f.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == RiskLevel.HIGH)
        medium_count = sum(1 for f in findings if f.severity == RiskLevel.MEDIUM)

        score = 100.0
        score -= critical_count * 40
        score -= high_count * 15
        score -= medium_count * 5
        score = max(0, score)

        # Determine status
        if critical_count > 0:
            status = ComplianceStatus.NON_COMPLIANT
        elif high_count > 1:
            status = ComplianceStatus.PARTIAL
        elif len(findings) > 0:
            status = ComplianceStatus.PARTIAL
        else:
            status = ComplianceStatus.COMPLIANT

        summary = (
            f"EU AI Act assessment: System classified as '{risk_class}' risk. "
            f"Found {len(findings)} compliance requirements. "
            f"{'CRITICAL: This system is prohibited.' if risk_class == 'prohibited' else ''}"
        )

        return FrameworkAssessment(
            framework_name=self.name,
            framework_version=self.version,
            overall_status=status,
            score=score,
            findings=findings,
            summary=summary
        )
