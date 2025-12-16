"""NIST AI Risk Management Framework."""

from typing import List
from .base import ComplianceFramework
from ..assessor.models import (
    AISystemInfo, FrameworkAssessment, Finding,
    RiskLevel, ComplianceStatus
)


class NISTFramework(ComplianceFramework):
    """NIST AI RMF 1.0 compliance assessment."""

    def __init__(self):
        """Initialize NIST AI RMF framework."""
        super().__init__("NIST AI RMF", "1.0")

    def get_requirements(self) -> List[str]:
        """Get NIST AI RMF requirements."""
        return [
            "Governance",
            "Mapping context and risks",
            "Measuring risks",
            "Managing risks",
            "Validity and reliability",
            "Safety",
            "Security and resilience",
            "Transparency and accountability",
            "Fairness and bias management",
            "Privacy enhancement"
        ]

    def assess(self, system_info: AISystemInfo) -> FrameworkAssessment:
        """Assess AI system against NIST AI RMF."""
        findings = []

        # GOVERN - Governance and oversight
        findings.append(Finding(
            id="nist-001",
            category="Governance (GOVERN)",
            title="AI governance structure required",
            description="Establish organizational governance for AI risk management including "
                       "roles, responsibilities, and accountability.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) AI governance committee, 2) Clear roles and responsibilities, "
                          "3) Risk tolerance levels, 4) Policies and procedures, 5) Regular reviews",
            references=["NIST AI RMF GOVERN"]
        ))

        # MAP - Context and risk identification
        findings.append(Finding(
            id="nist-002",
            category="Risk Mapping (MAP)",
            title="AI risk mapping and context assessment needed",
            description="Document the AI system's context, categorize impacts, and map risks.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Document: 1) Intended use and context, 2) Potential impacts, "
                          "3) Stakeholder analysis, 4) Risk categories, 5) Dependencies",
            references=["NIST AI RMF MAP"]
        ))

        # MEASURE - Risk measurement
        findings.append(Finding(
            id="nist-003",
            category="Risk Measurement (MEASURE)",
            title="Risk measurement and testing required",
            description="Implement systematic testing and evaluation of AI risks.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Performance metrics, 2) Bias testing, 3) Robustness evaluation, "
                          "4) Security testing, 5) Continuous monitoring",
            references=["NIST AI RMF MEASURE"]
        ))

        # MANAGE - Risk management
        findings.append(Finding(
            id="nist-004",
            category="Risk Management (MANAGE)",
            title="Risk mitigation and response required",
            description="Implement risk treatment and incident response capabilities.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Establish: 1) Risk mitigation controls, 2) Incident response plan, "
                          "3) Change management, 4) Third-party risk management, 5) Decommissioning process",
            references=["NIST AI RMF MANAGE"]
        ))

        # Trustworthiness characteristics

        # Validity and reliability
        findings.append(Finding(
            id="nist-005",
            category="Trustworthiness",
            title="Validity and reliability testing required",
            description="Ensure AI system produces valid, reliable, and reproducible outputs.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Validation testing, 2) Performance benchmarks, "
                          "3) Reproducibility checks, 4) Edge case testing, 5) Continuous validation",
            references=["NIST AI RMF - Valid and Reliable"]
        ))

        # Safety
        if system_info.use_case in ["autonomous_vehicle", "medical", "critical_infrastructure"]:
            findings.append(Finding(
                id="nist-006",
                category="Trustworthiness",
                title="Safety assurance critical for high-risk system",
                description="High-risk AI systems require comprehensive safety assurance.",
                severity=RiskLevel.CRITICAL,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Safety case development, 2) Failure mode analysis, "
                              "3) Safe fallback mechanisms, 4) Emergency stop capabilities, "
                              "5) Safety monitoring and alerts",
                references=["NIST AI RMF - Safe"]
            ))

        # Security and resilience
        findings.append(Finding(
            id="nist-007",
            category="Trustworthiness",
            title="Security and resilience measures required",
            description="Protect AI system from adversarial attacks and ensure resilience.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Adversarial robustness testing, 2) Input validation, "
                          "3) Model security controls, 4) Incident detection, 5) Recovery procedures",
            references=["NIST AI RMF - Secure and Resilient"]
        ))

        # Transparency and accountability
        findings.append(Finding(
            id="nist-008",
            category="Trustworthiness",
            title="Transparency and explainability needed",
            description="Provide transparency into AI system functioning and decisions.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Model documentation, 2) Decision explanations, "
                          "3) Audit trails, 4) Performance reporting, 5) Stakeholder communication",
            references=["NIST AI RMF - Accountable and Transparent"]
        ))

        # Fairness and bias
        findings.append(Finding(
            id="nist-009",
            category="Trustworthiness",
            title="Fairness and bias assessment required",
            description="Test for and mitigate harmful bias and ensure fairness.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Bias testing across demographics, 2) Fairness metrics, "
                          "3) Bias mitigation techniques, 4) Diverse training data, 5) Regular audits",
            references=["NIST AI RMF - Fair with Harmful Bias Managed"]
        ))

        # Privacy
        if any(dt in ["personal", "pii", "health", "biometric"] for dt in system_info.data_types):
            findings.append(Finding(
                id="nist-010",
                category="Trustworthiness",
                title="Privacy-enhancing techniques required",
                description="Implement privacy controls for personal data processing.",
                severity=RiskLevel.HIGH,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Data minimization, 2) De-identification, "
                              "3) Privacy-preserving ML, 4) Access controls, 5) Privacy monitoring",
                references=["NIST AI RMF - Privacy Enhanced"]
            ))

        # Calculate score
        critical_count = sum(1 for f in findings if f.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == RiskLevel.HIGH)
        medium_count = sum(1 for f in findings if f.severity == RiskLevel.MEDIUM)

        score = 100.0
        score -= critical_count * 30
        score -= high_count * 12
        score -= medium_count * 5
        score = max(0, score)

        if critical_count > 0:
            status = ComplianceStatus.PARTIAL
        elif high_count > 2:
            status = ComplianceStatus.PARTIAL
        else:
            status = ComplianceStatus.PARTIAL  # Assume partial until proven compliant

        summary = (
            f"NIST AI RMF assessment found {len(findings)} areas requiring attention across "
            f"the four functions (GOVERN, MAP, MEASURE, MANAGE) and trustworthiness characteristics."
        )

        return FrameworkAssessment(
            framework_name=self.name,
            framework_version=self.version,
            overall_status=status,
            score=score,
            findings=findings,
            summary=summary
        )
