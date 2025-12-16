"""HIPAA compliance framework for healthcare AI."""

from typing import List
from .base import ComplianceFramework
from ..assessor.models import (
    AISystemInfo, FrameworkAssessment, Finding,
    RiskLevel, ComplianceStatus
)


class HIPAAFramework(ComplianceFramework):
    """HIPAA compliance assessment for healthcare AI."""

    def __init__(self):
        """Initialize HIPAA framework."""
        super().__init__("HIPAA", "2013 Omnibus Rule")

    def get_requirements(self) -> List[str]:
        """Get HIPAA requirements."""
        return [
            "Privacy Rule compliance",
            "Security Rule - Administrative safeguards",
            "Security Rule - Physical safeguards",
            "Security Rule - Technical safeguards",
            "Breach notification",
            "Business associate agreements",
            "Minimum necessary standard",
            "Patient rights"
        ]

    def assess(self, system_info: AISystemInfo) -> FrameworkAssessment:
        """Assess AI system for HIPAA compliance."""
        findings = []

        # Check if system processes PHI
        processes_phi = any(
            dt in ["health", "medical", "phi", "ehr"]
            for dt in system_info.data_types
        ) or system_info.use_case in ["health_diagnosis", "medical", "healthcare"]

        if not processes_phi:
            # HIPAA not applicable
            return FrameworkAssessment(
                framework_name=self.name,
                framework_version=self.version,
                overall_status=ComplianceStatus.NOT_APPLICABLE,
                score=100.0,
                findings=[],
                summary="HIPAA not applicable - system does not process PHI."
            )

        # Privacy Rule
        findings.append(Finding(
            id="hipaa-001",
            category="Privacy Rule",
            title="Privacy Rule compliance required for PHI",
            description="AI system processes Protected Health Information and must comply with "
                       "HIPAA Privacy Rule requirements.",
            severity=RiskLevel.CRITICAL,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Minimum necessary standard, 2) Patient authorization, "
                          "3) Notice of privacy practices, 4) Patient access rights, "
                          "5) Privacy policies and procedures",
            references=["45 CFR Part 160, Part 164 Subpart E"]
        ))

        # Administrative safeguards
        findings.append(Finding(
            id="hipaa-002",
            category="Security Rule - Administrative",
            title="Administrative safeguards required",
            description="Implement administrative measures to protect ePHI.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Security management process, 2) Security officer designation, "
                          "3) Workforce security, 4) Access management, 5) Security awareness training, "
                          "6) Contingency planning, 7) Business associate contracts",
            references=["45 CFR § 164.308"]
        ))

        # Physical safeguards
        findings.append(Finding(
            id="hipaa-003",
            category="Security Rule - Physical",
            title="Physical safeguards for ePHI required",
            description="Protect physical access to systems containing ePHI.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Facility access controls, 2) Workstation use policies, "
                          "3) Workstation security, 4) Device and media controls",
            references=["45 CFR § 164.310"]
        ))

        # Technical safeguards
        findings.append(Finding(
            id="hipaa-004",
            category="Security Rule - Technical",
            title="Technical safeguards for ePHI required",
            description="Implement technical measures to protect ePHI in the AI system.",
            severity=RiskLevel.CRITICAL,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Unique user identification, 2) Emergency access procedures, "
                          "3) Automatic logoff, 4) Encryption and decryption, 5) Audit controls, "
                          "6) Integrity controls, 7) Person/entity authentication, 8) Transmission security",
            references=["45 CFR § 164.312"]
        ))

        # Risk analysis
        findings.append(Finding(
            id="hipaa-005",
            category="Risk Analysis",
            title="Security risk analysis required",
            description="Conduct comprehensive risk analysis for AI system handling ePHI.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Conduct risk analysis: 1) Identify ePHI locations, 2) Identify threats and vulnerabilities, "
                          "3) Assess current security measures, 4) Determine likelihood and impact, "
                          "5) Document risk levels, 6) Implement risk management measures",
            references=["45 CFR § 164.308(a)(1)(ii)(A)"]
        ))

        # Breach notification
        findings.append(Finding(
            id="hipaa-006",
            category="Breach Notification",
            title="Breach notification procedures required",
            description="Establish procedures for detecting and reporting PHI breaches.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Establish: 1) Breach detection mechanisms, 2) Risk assessment process, "
                          "3) Notification procedures, 4) Documentation requirements, "
                          "5) Mitigation procedures",
            references=["45 CFR Part 164 Subpart D"]
        ))

        # Business associate agreements
        findings.append(Finding(
            id="hipaa-007",
            category="Business Associates",
            title="Business associate agreements required",
            description="Ensure BAAs are in place for all third parties accessing PHI.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Establish: 1) BAA with all vendors, 2) Vendor security assessments, "
                          "3) Subcontractor flow-down requirements, 4) Vendor monitoring, "
                          "5) Termination procedures",
            references=["45 CFR § 164.308(b)"]
        ))

        # AI-specific considerations
        findings.append(Finding(
            id="hipaa-008",
            category="AI-Specific",
            title="AI model security for PHI required",
            description="Protect AI models trained on PHI from extraction and misuse.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Model access controls, 2) Training data de-identification, "
                          "3) Differential privacy, 4) Model theft prevention, "
                          "5) Secure model deployment",
            references=["HIPAA Security Rule - AI Extensions"]
        ))

        # De-identification for AI training
        if system_info.model_info and "training" in str(system_info.model_info).lower():
            findings.append(Finding(
                id="hipaa-009",
                category="De-identification",
                title="De-identification of training data recommended",
                description="Consider using de-identified data for AI model training when possible.",
                severity=RiskLevel.MEDIUM,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Expert determination or safe harbor de-identification, "
                              "2) Limited data set with data use agreement, 3) Re-identification risk assessment, "
                              "4) Synthetic data generation, 5) Privacy-preserving techniques",
                references=["45 CFR § 164.514"]
            ))

        # Calculate score
        critical_count = sum(1 for f in findings if f.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == RiskLevel.HIGH)
        medium_count = sum(1 for f in findings if f.severity == RiskLevel.MEDIUM)

        score = 100.0
        score -= critical_count * 35
        score -= high_count * 15
        score -= medium_count * 5
        score = max(0, score)

        if critical_count > 0:
            status = ComplianceStatus.NON_COMPLIANT
        elif high_count > 1:
            status = ComplianceStatus.PARTIAL
        else:
            status = ComplianceStatus.PARTIAL

        summary = (
            f"HIPAA assessment found {len(findings)} compliance requirements for AI system "
            f"processing Protected Health Information. Critical areas include Privacy Rule, "
            f"Security Rule technical safeguards, and AI-specific PHI protections."
        )

        return FrameworkAssessment(
            framework_name=self.name,
            framework_version=self.version,
            overall_status=status,
            score=score,
            findings=findings,
            summary=summary
        )
