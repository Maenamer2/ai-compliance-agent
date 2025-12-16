"""GDPR (General Data Protection Regulation) compliance framework."""

from typing import List
from .base import ComplianceFramework
from ..assessor.models import (
    AISystemInfo, FrameworkAssessment, Finding,
    RiskLevel, ComplianceStatus
)


class GDPRFramework(ComplianceFramework):
    """GDPR compliance assessment."""

    def __init__(self):
        """Initialize GDPR framework."""
        super().__init__("GDPR", "2016/679")

    def get_requirements(self) -> List[str]:
        """Get GDPR requirements."""
        return [
            "Lawful basis for processing",
            "Data minimization",
            "Purpose limitation",
            "Accuracy",
            "Storage limitation",
            "Integrity and confidentiality",
            "Accountability",
            "Right to explanation (Article 22)",
            "Data protection by design and default",
            "Privacy impact assessment"
        ]

    def assess(self, system_info: AISystemInfo) -> FrameworkAssessment:
        """Assess AI system for GDPR compliance."""
        findings = []

        # Check for personal data processing
        has_personal_data = any(
            dt in ["personal", "pii", "biometric", "health", "financial"]
            for dt in system_info.data_types
        )

        if has_personal_data:
            # Article 22 - Automated decision-making
            if system_info.use_case in ["credit_scoring", "hiring", "health_diagnosis", "legal"]:
                findings.append(Finding(
                    id="gdpr-001",
                    category="Automated Decision-Making",
                    title="High-risk automated decision-making detected",
                    description=f"The AI system is used for {system_info.use_case} which involves "
                               "automated decision-making with legal or similarly significant effects. "
                               "GDPR Article 22 requires explicit consent or legal basis, and the right "
                               "to explanation must be provided.",
                    severity=RiskLevel.HIGH,
                    status=ComplianceStatus.UNKNOWN,
                    recommendation="Implement: 1) Explicit consent mechanism, 2) Right to human review, "
                                  "3) Right to explanation of decisions, 4) Document legal basis",
                    references=["GDPR Article 22", "GDPR Recital 71"]
                ))

            # Data minimization
            findings.append(Finding(
                id="gdpr-002",
                category="Data Minimization",
                title="Data minimization assessment required",
                description="Verify that only necessary personal data is collected and processed. "
                           "AI systems often collect excessive data for training.",
                severity=RiskLevel.MEDIUM,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Document what data is collected, why it's necessary, and implement "
                              "data minimization controls. Regularly review and delete unnecessary data.",
                references=["GDPR Article 5(1)(c)"]
            ))

            # Privacy by design
            findings.append(Finding(
                id="gdpr-003",
                category="Privacy by Design",
                title="Privacy by design and default required",
                description="Data protection measures must be integrated into the AI system design.",
                severity=RiskLevel.MEDIUM,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Pseudonymization, 2) Encryption, 3) Access controls, "
                              "4) Differential privacy for training data, 5) Privacy-preserving techniques",
                references=["GDPR Article 25"]
            ))

            # DPIA requirement
            if system_info.use_case in ["profiling", "monitoring", "biometric", "health_diagnosis"]:
                findings.append(Finding(
                    id="gdpr-004",
                    category="Impact Assessment",
                    title="Data Protection Impact Assessment (DPIA) required",
                    description="High-risk processing activities require a DPIA before deployment.",
                    severity=RiskLevel.HIGH,
                    status=ComplianceStatus.UNKNOWN,
                    recommendation="Conduct a DPIA that includes: 1) Description of processing, "
                                  "2) Necessity and proportionality assessment, 3) Risk assessment, "
                                  "4) Mitigation measures",
                    references=["GDPR Article 35"]
                ))

            # Cross-border transfers
            if system_info.deployment_region and "EU" not in system_info.deployment_region.upper():
                findings.append(Finding(
                    id="gdpr-005",
                    category="Cross-Border Transfer",
                    title="International data transfer safeguards needed",
                    description="Processing personal data outside the EU requires appropriate safeguards.",
                    severity=RiskLevel.HIGH,
                    status=ComplianceStatus.UNKNOWN,
                    recommendation="Implement: 1) Standard contractual clauses, 2) Adequacy decision verification, "
                                  "3) Additional safeguards per Schrems II, 4) Transfer impact assessment",
                    references=["GDPR Article 44-50", "Schrems II"]
                ))

        # Calculate compliance score
        critical_count = sum(1 for f in findings if f.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == RiskLevel.HIGH)
        medium_count = sum(1 for f in findings if f.severity == RiskLevel.MEDIUM)

        # Score based on findings
        score = 100.0
        score -= critical_count * 30
        score -= high_count * 15
        score -= medium_count * 5
        score = max(0, score)

        # Determine overall status
        if critical_count > 0:
            status = ComplianceStatus.NON_COMPLIANT
        elif high_count > 0:
            status = ComplianceStatus.PARTIAL
        elif len(findings) > 0:
            status = ComplianceStatus.PARTIAL
        else:
            status = ComplianceStatus.COMPLIANT

        summary = (
            f"GDPR assessment found {len(findings)} potential compliance issues. "
            f"Personal data processing detected: {has_personal_data}. "
            f"Key areas of concern: automated decision-making, data minimization, "
            f"and privacy by design requirements."
        )

        return FrameworkAssessment(
            framework_name=self.name,
            framework_version=self.version,
            overall_status=status,
            score=score,
            findings=findings,
            summary=summary
        )
