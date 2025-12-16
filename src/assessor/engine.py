"""Main assessment engine."""

import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime

from .models import (
    AISystemInfo, AssessmentResult, FrameworkAssessment,
    SecurityAssessment, Finding, RiskLevel, ComplianceStatus
)


class AIComplianceAssessor:
    """Main AI compliance and security assessment engine."""

    def __init__(self):
        """Initialize the assessor."""
        self.frameworks = {}
        self.security_checks = {}
        self._load_frameworks()
        self._load_security_checks()

    def _load_frameworks(self):
        """Load available compliance frameworks."""
        from ..frameworks import (
            GDPRFramework, EUAIActFramework, NISTFramework,
            ISO42001Framework, HIPAAFramework
        )

        self.frameworks = {
            "gdpr": GDPRFramework(),
            "eu_ai_act": EUAIActFramework(),
            "nist": NISTFramework(),
            "iso42001": ISO42001Framework(),
            "hipaa": HIPAAFramework(),
        }

    def _load_security_checks(self):
        """Load security assessment modules."""
        from ..security import (
            OWASPLLMChecker, AdversarialChecker, DataPrivacyChecker,
            ModelSecurityChecker, SupplyChainChecker
        )

        self.security_checks = {
            "owasp_llm": OWASPLLMChecker(),
            "adversarial": AdversarialChecker(),
            "data_privacy": DataPrivacyChecker(),
            "model_security": ModelSecurityChecker(),
            "supply_chain": SupplyChainChecker(),
        }

    def assess(
        self,
        system_info: Dict[str, Any],
        frameworks: Optional[List[str]] = None,
        security_checks: Optional[List[str]] = None,
        generate_report: bool = False
    ) -> AssessmentResult:
        """
        Perform a comprehensive assessment of an AI system.

        Args:
            system_info: Information about the AI system
            frameworks: List of compliance frameworks to check (None = all)
            security_checks: List of security checks to perform (None = all)
            generate_report: Whether to generate a detailed report

        Returns:
            AssessmentResult with findings and recommendations
        """
        # Parse system info
        ai_system = AISystemInfo(**system_info)

        # Generate assessment ID
        assessment_id = str(uuid.uuid4())

        # Determine which frameworks to assess
        fw_list = frameworks if frameworks else list(self.frameworks.keys())

        # Determine which security checks to run
        sec_list = security_checks if security_checks else list(self.security_checks.keys())

        # Run framework assessments
        framework_results = []
        for fw_name in fw_list:
            if fw_name in self.frameworks:
                result = self.frameworks[fw_name].assess(ai_system)
                framework_results.append(result)

        # Run security assessments
        security_results = []
        for sec_name in sec_list:
            if sec_name in self.security_checks:
                result = self.security_checks[sec_name].assess(ai_system)
                security_results.append(result)

        # Calculate overall metrics
        overall_score = self._calculate_overall_score(framework_results, security_results)
        overall_risk = self._calculate_overall_risk(framework_results, security_results)

        # Count findings
        total_findings = 0
        critical_findings = 0
        high_findings = 0

        for fw in framework_results:
            total_findings += len(fw.findings)
            critical_findings += sum(1 for f in fw.findings if f.severity == RiskLevel.CRITICAL)
            high_findings += sum(1 for f in fw.findings if f.severity == RiskLevel.HIGH)

        for sec in security_results:
            total_findings += len(sec.findings)
            critical_findings += sum(1 for f in sec.findings if f.severity == RiskLevel.CRITICAL)
            high_findings += sum(1 for f in sec.findings if f.severity == RiskLevel.HIGH)

        # Create assessment result
        result = AssessmentResult(
            assessment_id=assessment_id,
            system_info=ai_system,
            frameworks=framework_results,
            security=security_results,
            overall_score=overall_score,
            overall_risk=overall_risk,
            total_findings=total_findings,
            critical_findings=critical_findings,
            high_findings=high_findings
        )

        return result

    def _calculate_overall_score(
        self,
        frameworks: List[FrameworkAssessment],
        security: List[SecurityAssessment]
    ) -> float:
        """Calculate overall assessment score."""
        scores = []

        for fw in frameworks:
            scores.append(fw.score)

        for sec in security:
            scores.append(sec.score)

        if not scores:
            return 0.0

        return sum(scores) / len(scores)

    def _calculate_overall_risk(
        self,
        frameworks: List[FrameworkAssessment],
        security: List[SecurityAssessment]
    ) -> RiskLevel:
        """Calculate overall risk level."""
        risk_levels = []

        # Map compliance status to risk
        status_risk_map = {
            ComplianceStatus.NON_COMPLIANT: RiskLevel.CRITICAL,
            ComplianceStatus.PARTIAL: RiskLevel.MEDIUM,
            ComplianceStatus.COMPLIANT: RiskLevel.LOW,
            ComplianceStatus.NOT_APPLICABLE: RiskLevel.MINIMAL,
        }

        for fw in frameworks:
            if fw.overall_status in status_risk_map:
                risk_levels.append(status_risk_map[fw.overall_status])

        for sec in security:
            risk_levels.append(sec.overall_risk)

        if not risk_levels:
            return RiskLevel.MEDIUM

        # Return highest risk level
        risk_priority = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.MINIMAL]
        for risk in risk_priority:
            if risk in risk_levels:
                return risk

        return RiskLevel.MEDIUM

    def list_frameworks(self) -> List[str]:
        """List available compliance frameworks."""
        return list(self.frameworks.keys())

    def list_security_checks(self) -> List[str]:
        """List available security checks."""
        return list(self.security_checks.keys())
