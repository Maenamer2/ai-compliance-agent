"""ISO/IEC 42001 AI Management System compliance framework."""

from typing import List
from .base import ComplianceFramework
from ..assessor.models import (
    AISystemInfo, FrameworkAssessment, Finding,
    RiskLevel, ComplianceStatus
)


class ISO42001Framework(ComplianceFramework):
    """ISO/IEC 42001:2023 compliance assessment."""

    def __init__(self):
        """Initialize ISO 42001 framework."""
        super().__init__("ISO/IEC 42001", "2023")

    def get_requirements(self) -> List[str]:
        """Get ISO 42001 requirements."""
        return [
            "Context of the organization",
            "Leadership and commitment",
            "AI management system planning",
            "Support and resources",
            "Operational planning and control",
            "Impact assessment",
            "Data management",
            "AI system development and deployment",
            "Performance evaluation",
            "Continual improvement"
        ]

    def assess(self, system_info: AISystemInfo) -> FrameworkAssessment:
        """Assess AI system for ISO 42001 compliance."""
        findings = []

        # Clause 4: Context of the organization
        findings.append(Finding(
            id="iso42001-001",
            category="Organizational Context",
            title="AI management system scope definition required",
            description="Define the scope and boundaries of the AI management system.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Document: 1) Organization context, 2) Stakeholder needs, "
                          "3) AIMS scope, 4) Applicable requirements, 5) AI objectives",
            references=["ISO/IEC 42001:2023 Clause 4"]
        ))

        # Clause 5: Leadership
        findings.append(Finding(
            id="iso42001-002",
            category="Leadership",
            title="Leadership commitment and AI policy required",
            description="Top management must demonstrate leadership and commitment to the AIMS.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Establish: 1) AI policy statement, 2) Roles and responsibilities, "
                          "3) Resource allocation, 4) Communication plan, 5) Management commitment",
            references=["ISO/IEC 42001:2023 Clause 5"]
        ))

        # Clause 6: Planning
        findings.append(Finding(
            id="iso42001-003",
            category="Planning",
            title="AI risk assessment and treatment required",
            description="Conduct systematic risk assessment for AI systems.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Risk assessment methodology, 2) Risk criteria, "
                          "3) Risk treatment plan, 4) AI objectives, 5) Planning for changes",
            references=["ISO/IEC 42001:2023 Clause 6"]
        ))

        # Clause 7: Support
        findings.append(Finding(
            id="iso42001-004",
            category="Support",
            title="Competence and awareness programs needed",
            description="Ensure personnel have necessary competence for AI system development and operation.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Competence requirements, 2) Training programs, "
                          "3) Awareness initiatives, 4) Communication channels, 5) Documentation control",
            references=["ISO/IEC 42001:2023 Clause 7"]
        ))

        # Clause 8: Operation - Impact Assessment
        findings.append(Finding(
            id="iso42001-005",
            category="Impact Assessment",
            title="AI impact assessment required",
            description="Conduct impact assessment for AI systems throughout the lifecycle.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Assess: 1) Societal impact, 2) Environmental impact, "
                          "3) Fundamental rights, 4) Ethical implications, 5) Stakeholder effects",
            references=["ISO/IEC 42001:2023 Clause 8.2"]
        ))

        # Data management
        findings.append(Finding(
            id="iso42001-006",
            category="Data Management",
            title="Data quality and governance required",
            description="Establish data management controls for AI systems.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Data quality controls, 2) Data governance, "
                          "3) Data provenance tracking, 4) Bias detection, 5) Data lifecycle management",
            references=["ISO/IEC 42001:2023 Clause 8.3"]
        ))

        # AI system development
        findings.append(Finding(
            id="iso42001-007",
            category="Development",
            title="Systematic AI development process required",
            description="Follow structured approach for AI system development and deployment.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Establish: 1) Development methodology, 2) Validation and testing, "
                          "3) Documentation requirements, 4) Version control, 5) Change management",
            references=["ISO/IEC 42001:2023 Clause 8.4"]
        ))

        # Human oversight
        findings.append(Finding(
            id="iso42001-008",
            category="Operation",
            title="Human oversight mechanisms required",
            description="Implement appropriate human oversight for AI systems.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Human oversight controls, 2) Override capabilities, "
                          "3) Review processes, 4) Escalation procedures, 5) Training for operators",
            references=["ISO/IEC 42001:2023 Clause 8.5"]
        ))

        # Clause 9: Performance evaluation
        findings.append(Finding(
            id="iso42001-009",
            category="Performance Evaluation",
            title="Monitoring and measurement required",
            description="Establish metrics and monitoring for AI system performance.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Performance metrics, 2) Monitoring processes, "
                          "3) Internal audits, 4) Management review, 5) Compliance evaluation",
            references=["ISO/IEC 42001:2023 Clause 9"]
        ))

        # Clause 10: Improvement
        findings.append(Finding(
            id="iso42001-010",
            category="Continual Improvement",
            title="Continual improvement process required",
            description="Establish processes for ongoing improvement of the AI management system.",
            severity=RiskLevel.LOW,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Nonconformity management, 2) Corrective actions, "
                          "3) Continuous improvement, 4) Lessons learned, 5) Innovation process",
            references=["ISO/IEC 42001:2023 Clause 10"]
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

        status = ComplianceStatus.PARTIAL

        summary = (
            f"ISO/IEC 42001 assessment found {len(findings)} management system requirements. "
            f"This standard provides a comprehensive framework for AI governance and management."
        )

        return FrameworkAssessment(
            framework_name=self.name,
            framework_version=self.version,
            overall_status=status,
            score=score,
            findings=findings,
            summary=summary
        )
