"""Data privacy security checker."""

from typing import List
from .base import SecurityChecker
from ..assessor.models import (
    AISystemInfo, SecurityAssessment, Finding,
    RiskLevel, ComplianceStatus
)


class DataPrivacyChecker(SecurityChecker):
    """Data privacy and PII protection assessment."""

    def __init__(self):
        """Initialize data privacy checker."""
        super().__init__("Data Privacy")

    def get_checks(self) -> List[str]:
        """Get data privacy checks."""
        return [
            "PII detection and handling",
            "Data minimization",
            "Encryption",
            "Access controls",
            "Data retention",
            "Privacy-preserving ML"
        ]

    def assess(self, system_info: AISystemInfo) -> SecurityAssessment:
        """Assess AI system for data privacy."""
        findings = []
        recommendations = []

        has_sensitive_data = any(
            dt in ["personal", "pii", "health", "financial", "biometric"]
            for dt in system_info.data_types
        )

        if not has_sensitive_data:
            return SecurityAssessment(
                category=self.category,
                overall_risk=RiskLevel.LOW,
                score=90.0,
                findings=[Finding(
                    id="privacy-001",
                    category="Data Assessment",
                    title="No sensitive data detected",
                    description="System does not appear to process sensitive personal data.",
                    severity=RiskLevel.LOW,
                    status=ComplianceStatus.UNKNOWN,
                    recommendation="Continue to monitor data types and reassess if data handling changes.",
                    references=[]
                )],
                recommendations=["Monitor for changes in data handling"]
            )

        # PII detection and handling
        findings.append(Finding(
            id="privacy-002",
            category="PII Protection",
            title="PII detection and protection required",
            description="System processes personal/sensitive data and must implement PII protection.",
            severity=RiskLevel.CRITICAL,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) PII detection and classification, 2) Data masking/redaction, "
                          "3) De-identification, 4) Tokenization, 5) Access logging",
            references=["NIST Privacy Framework"]
        ))
        recommendations.append("Implement comprehensive PII protection")

        # Data minimization
        findings.append(Finding(
            id="privacy-003",
            category="Data Minimization",
            title="Data minimization principle required",
            description="Collect and process only the minimum necessary personal data.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Purpose specification, 2) Data inventory, "
                          "3) Necessity assessment, 4) Regular data reviews, "
                          "5) Automated data deletion",
            references=["GDPR Article 5(1)(c)", "Privacy by Design"]
        ))
        recommendations.append("Minimize data collection and retention")

        # Encryption
        findings.append(Finding(
            id="privacy-004",
            category="Encryption",
            title="Encryption for data at rest and in transit required",
            description="Sensitive data must be encrypted at rest and in transit.",
            severity=RiskLevel.CRITICAL,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) TLS 1.3 for data in transit, 2) AES-256 for data at rest, "
                          "3) End-to-end encryption where appropriate, 4) Key management, "
                          "5) Encrypted backups",
            references=["NIST SP 800-175B"]
        ))
        recommendations.append("Encrypt all sensitive data")

        # Access controls
        findings.append(Finding(
            id="privacy-005",
            category="Access Control",
            title="Strong access controls required",
            description="Implement strict access controls for personal data.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Role-based access control (RBAC), 2) Least privilege, "
                          "3) Multi-factor authentication, 4) Access logging and monitoring, "
                          "5) Regular access reviews",
            references=["NIST SP 800-53"]
        ))
        recommendations.append("Enforce strict access controls")

        # Data retention and deletion
        findings.append(Finding(
            id="privacy-006",
            category="Data Retention",
            title="Data retention and deletion policies required",
            description="Establish clear policies for data retention and secure deletion.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Retention schedules, 2) Automated deletion, "
                          "3) Secure data wiping, 4) Backup deletion, "
                          "5) Right to erasure support",
            references=["GDPR Article 17"]
        ))
        recommendations.append("Define and enforce data retention policies")

        # Privacy-preserving ML techniques
        findings.append(Finding(
            id="privacy-007",
            category="Privacy-Preserving ML",
            title="Privacy-preserving machine learning recommended",
            description="Use privacy-preserving techniques to protect training and inference data.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Differential privacy, 2) Federated learning, "
                          "3) Homomorphic encryption, 4) Secure multi-party computation, "
                          "5) Synthetic data generation",
            references=["Privacy-Preserving ML"]
        ))
        recommendations.append("Adopt privacy-preserving ML techniques")

        # Data anonymization
        findings.append(Finding(
            id="privacy-008",
            category="Anonymization",
            title="Data anonymization for non-production use",
            description="Anonymize or pseudonymize data for development, testing, and analytics.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) K-anonymity techniques, 2) Data masking, "
                          "3) Synthetic test data, 4) Production data restrictions, "
                          "5) Re-identification risk assessment",
            references=["GDPR Article 89"]
        ))
        recommendations.append("Use anonymized data for non-production environments")

        # Cross-border data transfers
        if system_info.deployment_region and "," in str(system_info.deployment_region):
            findings.append(Finding(
                id="privacy-009",
                category="Cross-Border Transfer",
                title="Cross-border data transfer protections needed",
                description="Multi-region deployment requires cross-border transfer safeguards.",
                severity=RiskLevel.HIGH,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Transfer impact assessment, 2) Standard contractual clauses, "
                              "3) Binding corporate rules, 4) Data localization where required, "
                              "5) Transfer logging",
                references=["GDPR Chapter V"]
            ))
            recommendations.append("Safeguard cross-border data transfers")

        # Data breach detection and response
        findings.append(Finding(
            id="privacy-010",
            category="Breach Response",
            title="Data breach detection and response required",
            description="Implement mechanisms to detect and respond to data breaches.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Breach detection systems, 2) Incident response plan, "
                          "3) Breach notification procedures, 4) Forensic capabilities, "
                          "5) Regular breach drills",
            references=["GDPR Article 33-34"]
        ))
        recommendations.append("Establish breach detection and response procedures")

        # Calculate score
        critical_count = sum(1 for f in findings if f.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == RiskLevel.HIGH)
        medium_count = sum(1 for f in findings if f.severity == RiskLevel.MEDIUM)

        score = 100.0
        score -= critical_count * 30
        score -= high_count * 10
        score -= medium_count * 5
        score = max(0, score)

        # Determine overall risk
        if critical_count > 0:
            overall_risk = RiskLevel.CRITICAL
        elif high_count >= 3:
            overall_risk = RiskLevel.HIGH
        elif high_count > 0:
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
