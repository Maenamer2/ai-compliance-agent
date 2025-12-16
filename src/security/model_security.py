"""Model security checker."""

from typing import List
from .base import SecurityChecker
from ..assessor.models import (
    AISystemInfo, SecurityAssessment, Finding,
    RiskLevel
)


class ModelSecurityChecker(SecurityChecker):
    """Model-specific security assessment."""

    def __init__(self):
        """Initialize model security checker."""
        super().__init__("Model Security")

    def get_checks(self) -> List[str]:
        """Get model security checks."""
        return [
            "Model access controls",
            "Model versioning",
            "Model integrity",
            "Secure deployment",
            "Model monitoring"
        ]

    def assess(self, system_info: AISystemInfo) -> SecurityAssessment:
        """Assess AI model security."""
        findings = []
        recommendations = []

        # Model access controls
        findings.append(Finding(
            id="model-001",
            category="Access Control",
            title="Model access controls required",
            description="Protect AI models from unauthorized access and modification.",
            severity=RiskLevel.HIGH,
            status=RiskLevel.HIGH,
            recommendation="Implement: 1) Authentication for model access, 2) Authorization checks, "
                          "3) Model file encryption, 4) Secure model storage, "
                          "5) Access logging and auditing",
            references=["AI Model Security Best Practices"]
        ))
        recommendations.append("Implement strong model access controls")

        # Model integrity and signing
        findings.append(Finding(
            id="model-002",
            category="Model Integrity",
            title="Model integrity verification required",
            description="Verify model integrity to prevent tampering and ensure authenticity.",
            severity=RiskLevel.HIGH,
            status=RiskLevel.HIGH,
            recommendation="Implement: 1) Model signing and verification, 2) Checksums/hashes, "
                          "3) Tamper detection, 4) Secure model registry, "
                          "5) Version control for models",
            references=["Supply Chain Security"]
        ))
        recommendations.append("Sign and verify model integrity")

        # Secure model deployment
        findings.append(Finding(
            id="model-003",
            category="Secure Deployment",
            title="Secure model deployment practices required",
            description="Deploy models securely to prevent exploitation.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Secure container images, 2) Network segmentation, "
                          "3) Secrets management, 4) Minimal runtime permissions, "
                          "5) Hardened deployment environment",
            references=["Container Security"]
        ))
        recommendations.append("Follow secure deployment practices")

        # Model versioning and rollback
        findings.append(Finding(
            id="model-004",
            category="Versioning",
            title="Model versioning and rollback capability required",
            description="Maintain model versions and ability to rollback if issues arise.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Model version control, 2) Deployment history, "
                          "3) Quick rollback procedures, 4) A/B testing capability, "
                          "5) Canary deployments",
            references=["MLOps Best Practices"]
        ))
        recommendations.append("Implement model versioning and rollback")

        # Model monitoring and drift detection
        findings.append(Finding(
            id="model-005",
            category="Monitoring",
            title="Model monitoring and drift detection required",
            description="Monitor model performance and detect data/concept drift.",
            severity=RiskLevel.HIGH,
            status=RiskLevel.HIGH,
            recommendation="Implement: 1) Performance monitoring, 2) Data drift detection, "
                          "3) Concept drift detection, 4) Anomaly detection, "
                          "5) Automated alerts and retraining triggers",
            references=["ML Monitoring"]
        ))
        recommendations.append("Monitor model performance and drift")

        # API security
        findings.append(Finding(
            id="model-006",
            category="API Security",
            title="Model API security controls required",
            description="Secure the API endpoints that serve the model.",
            severity=RiskLevel.HIGH,
            status=RiskLevel.HIGH,
            recommendation="Implement: 1) API authentication (OAuth, API keys), "
                          "2) Rate limiting, 3) Input validation, "
                          "4) Output sanitization, 5) TLS encryption, 6) CORS policies",
            references=["OWASP API Security"]
        ))
        recommendations.append("Secure model API endpoints")

        # Model provenance
        findings.append(Finding(
            id="model-007",
            category="Provenance",
            title="Model provenance tracking recommended",
            description="Track model lineage, training data, and development history.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Model cards, 2) Training data provenance, "
                          "3) Experiment tracking, 4) Reproducibility documentation, "
                          "5) Dependency tracking",
            references=["Model Cards for Model Reporting"]
        ))
        recommendations.append("Document model provenance and lineage")

        # Secure inference
        findings.append(Finding(
            id="model-008",
            category="Secure Inference",
            title="Secure inference practices required",
            description="Protect inference process from attacks and data leakage.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Input sanitization, 2) Output filtering, "
                          "3) Inference sandboxing, 4) Resource limits, "
                          "5) Query logging for anomaly detection",
            references=["Secure ML Inference"]
        ))
        recommendations.append("Implement secure inference practices")

        # Model backup and disaster recovery
        findings.append(Finding(
            id="model-009",
            category="Business Continuity",
            title="Model backup and disaster recovery required",
            description="Ensure model availability through backups and disaster recovery.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Regular model backups, 2) Disaster recovery plan, "
                          "3) Multi-region redundancy, 4) Backup testing, "
                          "5) Recovery time objectives (RTO)",
            references=["Business Continuity Planning"]
        ))
        recommendations.append("Establish model backup and recovery procedures")

        # Environment isolation
        findings.append(Finding(
            id="model-010",
            category="Environment Isolation",
            title="Environment isolation required",
            description="Separate development, testing, and production environments.",
            severity=RiskLevel.MEDIUM,
            status=RiskLevel.MEDIUM,
            recommendation="Implement: 1) Separate environments, 2) Different credentials per environment, "
                          "3) Production data restrictions, 4) Promotion workflows, "
                          "5) Environment-specific configurations",
            references=["Environment Management"]
        ))
        recommendations.append("Isolate development and production environments")

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
