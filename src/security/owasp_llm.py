"""OWASP Top 10 for LLM Applications security checker."""

from typing import List
from .base import SecurityChecker
from ..assessor.models import (
    AISystemInfo, SecurityAssessment, Finding,
    RiskLevel, ComplianceStatus
)


class OWASPLLMChecker(SecurityChecker):
    """OWASP Top 10 for LLM Applications security assessment."""

    def __init__(self):
        """Initialize OWASP LLM checker."""
        super().__init__("OWASP LLM Security")

    def get_checks(self) -> List[str]:
        """Get OWASP LLM Top 10 checks."""
        return [
            "Prompt Injection",
            "Insecure Output Handling",
            "Training Data Poisoning",
            "Model Denial of Service",
            "Supply Chain Vulnerabilities",
            "Sensitive Information Disclosure",
            "Insecure Plugin Design",
            "Excessive Agency",
            "Overreliance",
            "Model Theft"
        ]

    def assess(self, system_info: AISystemInfo) -> SecurityAssessment:
        """Assess AI system for OWASP LLM vulnerabilities."""
        findings = []
        recommendations = []

        # Only assess LLM and generative systems
        if system_info.type.value not in ["llm", "generative", "multimodal"]:
            return SecurityAssessment(
                category=self.category,
                overall_risk=RiskLevel.MINIMAL,
                score=100.0,
                findings=[],
                recommendations=["OWASP LLM Top 10 primarily applies to LLM systems"]
            )

        # LLM01: Prompt Injection
        findings.append(Finding(
            id="owasp-llm-01",
            category="Prompt Injection",
            title="Prompt injection vulnerability risk",
            description="LLM systems are vulnerable to prompt injection attacks where malicious inputs "
                       "can manipulate the model to ignore instructions or perform unintended actions.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Input validation and sanitization, 2) Privilege control for system prompts, "
                          "3) Separate user input from instructions, 4) Content filtering, "
                          "5) Contextual awareness of input sources",
            references=["OWASP LLM01", "https://owasp.org/www-project-top-10-for-large-language-model-applications/"]
        ))
        recommendations.append("Implement robust prompt injection defenses")

        # LLM02: Insecure Output Handling
        findings.append(Finding(
            id="owasp-llm-02",
            category="Insecure Output Handling",
            title="Insecure handling of LLM outputs",
            description="LLM outputs can contain malicious content like XSS, SQL injection, or shell commands "
                       "if not properly validated before downstream use.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Output validation and encoding, 2) Sandboxing for code execution, "
                          "3) Content Security Policy, 4) Parameterized queries, 5) Output sanitization",
            references=["OWASP LLM02"]
        ))
        recommendations.append("Validate and sanitize all LLM outputs before use")

        # LLM03: Training Data Poisoning
        findings.append(Finding(
            id="owasp-llm-03",
            category="Training Data Poisoning",
            title="Training data poisoning risk",
            description="Malicious or biased data in training sets can compromise model behavior, "
                       "leading to backdoors, biases, or vulnerabilities.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Data provenance tracking, 2) Data validation and filtering, "
                          "3) Adversarial training, 4) Regular model audits, 5) Secure data pipelines",
            references=["OWASP LLM03"]
        ))
        recommendations.append("Verify training data integrity and provenance")

        # LLM04: Model Denial of Service
        findings.append(Finding(
            id="owasp-llm-04",
            category="Model Denial of Service",
            title="DoS vulnerability through resource exhaustion",
            description="Attackers can craft inputs that cause excessive resource consumption, "
                       "leading to service degradation or outages.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Rate limiting, 2) Input size limits, 3) Request queuing, "
                          "4) Resource monitoring, 5) Timeout controls, 6) Load balancing",
            references=["OWASP LLM04"]
        ))
        recommendations.append("Implement rate limiting and resource controls")

        # LLM05: Supply Chain Vulnerabilities
        findings.append(Finding(
            id="owasp-llm-05",
            category="Supply Chain",
            title="Supply chain security risks",
            description="Dependencies on third-party models, datasets, or plugins can introduce vulnerabilities.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Vendor security assessment, 2) Dependency scanning, "
                          "3) Model provenance verification, 4) Plugin security review, "
                          "5) Supply chain monitoring",
            references=["OWASP LLM05"]
        ))
        recommendations.append("Audit all third-party dependencies and models")

        # LLM06: Sensitive Information Disclosure
        findings.append(Finding(
            id="owasp-llm-06",
            category="Information Disclosure",
            title="Sensitive information leakage risk",
            description="LLMs may inadvertently reveal sensitive information from training data, "
                       "system prompts, or user inputs in their outputs.",
            severity=RiskLevel.CRITICAL,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Output filtering for PII/secrets, 2) Training data sanitization, "
                          "3) Prompt protection, 4) Context isolation, 5) Regular audits for leakage",
            references=["OWASP LLM06"]
        ))
        recommendations.append("Implement sensitive data detection and filtering")

        # LLM07: Insecure Plugin Design
        if system_info.architecture and "plugins" in str(system_info.architecture).lower():
            findings.append(Finding(
                id="owasp-llm-07",
                category="Plugin Security",
                title="Insecure plugin/extension design",
                description="LLM plugins may lack proper input validation and access controls, "
                           "allowing malicious use or privilege escalation.",
                severity=RiskLevel.HIGH,
                status=ComplianceStatus.UNKNOWN,
                recommendation="Implement: 1) Plugin input validation, 2) Least privilege access, "
                              "3) Plugin sandboxing, 4) Security review process, 5) Plugin authentication",
                references=["OWASP LLM07"]
            ))
            recommendations.append("Security review and sandbox all plugins")

        # LLM08: Excessive Agency
        findings.append(Finding(
            id="owasp-llm-08",
            category="Excessive Agency",
            title="Excessive autonomy and permissions",
            description="LLM systems with excessive permissions or autonomy can perform unintended "
                       "high-impact actions without proper authorization.",
            severity=RiskLevel.HIGH,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Least privilege principle, 2) Human-in-the-loop for high-impact actions, "
                          "3) Action approval workflows, 4) Permission boundaries, 5) Audit logging",
            references=["OWASP LLM08"]
        ))
        recommendations.append("Restrict LLM permissions and require approval for critical actions")

        # LLM09: Overreliance
        findings.append(Finding(
            id="owasp-llm-09",
            category="Overreliance",
            title="Overreliance on LLM outputs",
            description="Users or systems may over-rely on LLM outputs without verification, "
                       "leading to misinformation or poor decisions.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) Confidence scores, 2) Source citations, 3) Uncertainty indicators, "
                          "4) Human review for critical decisions, 5) User education on limitations",
            references=["OWASP LLM09"]
        ))
        recommendations.append("Educate users on LLM limitations and implement verification")

        # LLM10: Model Theft
        findings.append(Finding(
            id="owasp-llm-10",
            category="Model Theft",
            title="Model theft and extraction risk",
            description="Attackers may attempt to steal or replicate the model through API queries "
                       "or unauthorized access to model artifacts.",
            severity=RiskLevel.MEDIUM,
            status=ComplianceStatus.UNKNOWN,
            recommendation="Implement: 1) API rate limiting, 2) Query pattern monitoring, "
                          "3) Model access controls, 4) Watermarking, 5) Secure model storage",
            references=["OWASP LLM10"]
        ))
        recommendations.append("Protect against model extraction attacks")

        # Calculate overall score
        critical_count = sum(1 for f in findings if f.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == RiskLevel.HIGH)
        medium_count = sum(1 for f in findings if f.severity == RiskLevel.MEDIUM)

        score = 100.0
        score -= critical_count * 25
        score -= high_count * 10
        score -= medium_count * 5
        score = max(0, score)

        # Determine overall risk
        if critical_count > 0:
            overall_risk = RiskLevel.CRITICAL
        elif high_count >= 3:
            overall_risk = RiskLevel.HIGH
        elif high_count > 0 or medium_count > 0:
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
