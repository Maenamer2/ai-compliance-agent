"""Adversarial robustness security checker."""

from typing import List
from .base import SecurityChecker
from ..assessor.models import (
    AISystemInfo, SecurityAssessment, Finding,
    RiskLevel, ComplianceStatus
)


class AdversarialChecker(SecurityChecker):
    """Adversarial robustness and attack resistance assessment."""

    def __init__(self):
        """Initialize adversarial checker."""
        super().__init__("Adversarial Robustness")

    def get_checks(self) -> List[str]:
        """Get adversarial security checks."""
        return [
            "Evasion attacks",
            "Poisoning attacks",
            "Model inversion",
            "Membership inference",
            "Backdoor attacks",
            "Adversarial examples"
        ]

    def assess(self, system_info: AISystemInfo) -> SecurityAssessment:
        """Assess AI system for adversarial robustness."""
        findings = []
        recommendations = []

        # Evasion attacks
        findings.append(Finding(
            id="adv-001",
            category="Evasion Attacks",
            title="Adversarial evasion attack vulnerability",
            description="AI models are vulnerable to adversarial examples - carefully crafted inputs "
                       "designed to cause misclassification or incorrect outputs.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Adversarial training, 2) Input preprocessing/detection, "
                          "3) Ensemble methods, 4) Gradient masking, 5) Certified defenses, "
                          "6) Regular adversarial testing",
            references=["NIST AI 100-2e2023"]
        ))
        recommendations.append("Conduct adversarial robustness testing")

        # Model inversion attacks
        if any(dt in ["personal", "pii", "biometric", "health"] for dt in system_info.data_types):
            findings.append(Finding(
                id="adv-002",
                category="Model Inversion",
                title="Model inversion attack risk",
                description="Attackers may reconstruct sensitive training data by querying the model, "
                           "potentially exposing private information.",
                severity=RiskLevel.HIGH,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Differential privacy, 2) Query limiting, "
                              "3) Output perturbation, 4) Knowledge distillation, "
                              "5) Privacy-preserving training",
                references=["Privacy in ML"]
            ))
            recommendations.append("Implement differential privacy protections")

        # Membership inference attacks
        if any(dt in ["personal", "pii", "confidential"] for dt in system_info.data_types):
            findings.append(Finding(
                id="adv-003",
                category="Membership Inference",
                title="Membership inference vulnerability",
                description="Attackers can determine if specific data was in the training set, "
                           "potentially revealing confidential information.",
                severity=RiskLevel.MEDIUM,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Differential privacy, 2) Regularization, "
                              "3) Model ensembling, 4) Confidence calibration, "
                              "5) Membership inference testing",
                references=["Privacy Attacks on ML"]
            ))
            recommendations.append("Test and mitigate membership inference risks")

        # Backdoor attacks
        findings.append(Finding(
            id="adv-004",
            category="Backdoor Attacks",
            title="Backdoor/trojan attack vulnerability",
            description="Models may contain backdoors that activate on specific triggers, "
                       "causing malicious behavior while appearing normal otherwise.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Training data validation, 2) Backdoor detection scanning, "
                          "3) Model provenance tracking, 4) Activation analysis, "
                          "5) Neural cleanse techniques",
            references=["Backdoor Attacks on AI"]
        ))
        recommendations.append("Scan for backdoors and validate training data")

        # Data poisoning
        findings.append(Finding(
            id="adv-005",
            category="Data Poisoning",
            title="Training data poisoning vulnerability",
            description="Attackers may inject malicious data to corrupt model behavior, "
                       "especially in systems using online learning or user feedback.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Data validation and sanitization, 2) Anomaly detection, "
                          "3) Robust training algorithms, 4) Data provenance, "
                          "5) Regular model retraining with clean data",
            references=["Data Poisoning Attacks"]
        ))
        recommendations.append("Validate and monitor training data integrity")

        # Physical adversarial attacks (for vision systems)
        if system_info.type.value in ["vision", "multimodal"]:
            findings.append(Finding(
                id="adv-006",
                category="Physical Attacks",
                title="Physical adversarial attack vulnerability",
                description="Vision models are vulnerable to physical adversarial attacks like "
                           "adversarial patches or modified objects in the real world.",
                severity=RiskLevel.HIGH,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Multi-angle/multi-sensor fusion, 2) Physical attack detection, "
                              "3) Robustness to transformations, 4) Certified physical robustness, "
                              "5) Regular physical security testing",
                references=["Physical Adversarial Examples"]
            ))
            recommendations.append("Test resilience to physical adversarial examples")

        # Model extraction
        findings.append(Finding(
            id="adv-007",
            category="Model Extraction",
            title="Model extraction attack risk",
            description="Attackers can create a copy of the model by querying it and training "
                       "a substitute model, stealing intellectual property.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Query rate limiting, 2) API access controls, "
                          "3) Prediction obfuscation, 4) Watermarking, "
                          "5) Anomalous query detection",
            references=["Model Extraction Attacks"]
        ))
        recommendations.append("Implement protections against model extraction")

        # High-risk use cases need stronger guarantees
        if system_info.use_case in ["autonomous_vehicle", "medical", "security", "financial"]:
            findings.append(Finding(
                id="adv-008",
                category="High-Risk System",
                title="Enhanced adversarial robustness required for high-risk use case",
                description=f"The {system_info.use_case} use case requires certified adversarial "
                           "robustness and comprehensive security validation.",
                severity=RiskLevel.CRITICAL,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Certified adversarial defenses, 2) Formal verification, "
                              "3) Red team testing, 4) Continuous security monitoring, "
                              "5) Safety fallback mechanisms",
                references=["Safety-Critical AI"]
            ))
            recommendations.append("Obtain certified robustness guarantees")

        # Calculate score
        critical_count = sum(1 for f in findings if f.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == RiskLevel.HIGH)
        medium_count = sum(1 for f in findings if f.severity == RiskLevel.MEDIUM)

        score = 100.0
        score -= critical_count * 30
        score -= high_count * 12
        score -= medium_count * 5
        score = max(0, score)

        # Determine overall risk
        if critical_count > 0:
            overall_risk = RiskLevel.CRITICAL
        elif high_count >= 2:
            overall_risk = RiskLevel.HIGH
        elif high_count > 0 or medium_count > 2:
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
