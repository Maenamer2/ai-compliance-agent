"""Supply chain security checker."""

from typing import List
from .base import SecurityChecker
from ..assessor.models import (
    AISystemInfo, SecurityAssessment, Finding,
    RiskLevel
)


class SupplyChainChecker(SecurityChecker):
    """AI supply chain security assessment."""

    def __init__(self):
        """Initialize supply chain checker."""
        super().__init__("Supply Chain Security")

    def get_checks(self) -> List[str]:
        """Get supply chain security checks."""
        return [
            "Dependency scanning",
            "Third-party model verification",
            "Dataset provenance",
            "Library vulnerabilities",
            "Vendor security"
        ]

    def assess(self, system_info: AISystemInfo) -> SecurityAssessment:
        """Assess AI supply chain security."""
        findings = []
        recommendations = []

        # Dependency vulnerabilities
        findings.append(Finding(
            id="supply-001",
            category="Dependencies",
            title="Dependency vulnerability scanning required",
            description="AI systems often depend on numerous libraries that may contain vulnerabilities.",
            severity=RiskLevel.HIGH,
            status=RiskLevel.HIGH,
            recommendation="Implement: 1) Automated dependency scanning (Snyk, Dependabot), "
                          "2) Regular updates, 3) Vulnerability monitoring, "
                          "4) Software Bill of Materials (SBOM), 5) License compliance checks",
            references=["NIST SSDF"]
        ))
        recommendations.append("Scan and update dependencies regularly")

        # Third-party models
        findings.append(Finding(
            id="supply-002",
            category="Third-Party Models",
            title="Third-party model security assessment required",
            description="Using pre-trained models or model APIs from third parties introduces supply chain risks.",
            severity=RiskLevel.HIGH,
            status=RiskLevel.HIGH,
            recommendation="Implement: 1) Model provenance verification, 2) Vendor security assessment, "
                          "3) Model integrity checks, 4) Licensing review, "
                          "5) Model testing and validation before use",
            references=["ML Supply Chain Security"]
        ))
        recommendations.append("Vet and verify third-party models")

        # Training data provenance
        findings.append(Finding(
            id="supply-003",
            category="Data Provenance",
            title="Training data provenance and validation required",
            description="Verify the source and integrity of training datasets to prevent poisoning.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Data source documentation, 2) Data integrity verification, "
                          "3) License compliance, 4) Data quality assessment, "
                          "5) Poisoning detection",
            references=["Data Provenance"]
        ))
        recommendations.append("Document and verify training data sources")

        # Open source components
        findings.append(Finding(
            id="supply-004",
            category="Open Source",
            title="Open source component management required",
            description="Track and manage open source ML frameworks and libraries.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Open source inventory, 2) License compliance, "
                          "3) Security advisories monitoring, 4) Update procedures, "
                          "5) Alternative component evaluation",
            references=["Open Source Security"]
        ))
        recommendations.append("Manage open source components")

        # Model registries and repositories
        findings.append(Finding(
            id="supply-005",
            category="Model Repositories",
            title="Secure model registry and repository practices",
            description="Models from public repositories (HuggingFace, ModelZoo) may be malicious or compromised.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Model scanning before use, 2) Trusted sources only, "
                          "3) Model signature verification, 4) Sandboxed testing, "
                          "5) Internal model registry",
            references=["Model Repository Security"]
        ))
        recommendations.append("Use trusted model sources and verify integrity")

        # API and cloud service dependencies
        findings.append(Finding(
            id="supply-006",
            category="Cloud Services",
            title="Third-party API and cloud service security",
            description="Dependencies on external AI APIs and cloud services create supply chain risks.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Vendor security assessment, 2) SLA and data protection agreements, "
                          "3) Service availability monitoring, 4) Fallback strategies, "
                          "5) Data residency compliance",
            references=["Cloud Security Alliance"]
        ))
        recommendations.append("Assess and monitor third-party service providers")

        # Build pipeline security
        findings.append(Finding(
            id="supply-007",
            category="Build Security",
            title="Secure ML build and training pipelines",
            description="Protect the ML build, training, and deployment pipelines from compromise.",
            severity=RiskLevel.HIGH,
            status=RiskLevel.HIGH,
            recommendation="Implement: 1) Pipeline access controls, 2) Code signing, "
                          "3) Secure CI/CD, 4) Audit logging, "
                          "5) Integrity verification at each stage",
            references=["SLSA Framework"]
        ))
        recommendations.append("Secure ML pipelines end-to-end")

        # Malicious packages
        findings.append(Finding(
            id="supply-008",
            category="Package Security",
            title="Protection against malicious packages",
            description="Typosquatting and malicious packages in ML ecosystems (PyPI, npm) are increasing.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Package verification, 2) Private package repository, "
                          "3) Dependency pinning, 4) Code review for new dependencies, "
                          "5) Package integrity checks",
            references=["Package Security"]
        ))
        recommendations.append("Verify package authenticity")

        # Vendor security assessments
        findings.append(Finding(
            id="supply-009",
            category="Vendor Management",
            title="Vendor security assessments required",
            description="Conduct security assessments of all AI-related vendors and partners.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Vendor questionnaires, 2) Security certifications review, "
                          "3) Regular audits, 4) Contractual security requirements, "
                          "5) Incident notification requirements",
            references=["Third-Party Risk Management"]
        ))
        recommendations.append("Assess vendor security posture")

        # Update and patch management
        findings.append(Finding(
            id="supply-010",
            category="Patch Management",
            title="Update and patch management process required",
            description="Establish procedures for updating ML frameworks, libraries, and models.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Patch assessment process, 2) Testing before deployment, "
                          "3) Automated updates for critical patches, 4) Rollback procedures, "
                          "5) Update tracking and reporting",
            references=["Patch Management"]
        ))
        recommendations.append("Establish patch management procedures")

        # Calculate score
        critical_count = sum(1 for f in findings if f.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == RiskLevel.HIGH)
        medium_count = sum(1 for f in findings if f.severity == RiskLevel.MEDIUM)

        score = 100.0
        score -= critical_count * 30
        score -= high_count * 10
        score -= medium_count * 4
        score = max(0, score)

        # Determine overall risk
        if critical_count > 0:
            overall_risk = RiskLevel.CRITICAL
        elif high_count >= 2:
            overall_risk = RiskLevel.HIGH
        elif high_count > 0 or medium_count >= 4:
            overall_risk = RiskLevel.MEDIUM
        else:
            overall_risk = RiskLevel.LOW

        return SecurityAssessment(
            category=self.category,
            overall_risk=overall_risk,
            score=score,
            findings=findings,
            recommendations=recommendations
        )
