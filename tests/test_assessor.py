"""Tests for the AI compliance assessor."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.assessor import AIComplianceAssessor
from src.assessor.models import AISystemInfo, AISystemType


def test_assessor_initialization():
    """Test assessor initializes correctly."""
    assessor = AIComplianceAssessor()
    assert assessor is not None
    assert len(assessor.frameworks) > 0
    assert len(assessor.security_checks) > 0


def test_list_frameworks():
    """Test listing frameworks."""
    assessor = AIComplianceAssessor()
    frameworks = assessor.list_frameworks()
    assert "gdpr" in frameworks
    assert "eu_ai_act" in frameworks
    assert "nist" in frameworks
    assert "iso42001" in frameworks
    assert "hipaa" in frameworks


def test_list_security_checks():
    """Test listing security checks."""
    assessor = AIComplianceAssessor()
    checks = assessor.list_security_checks()
    assert "owasp_llm" in checks
    assert "adversarial" in checks
    assert "data_privacy" in checks
    assert "model_security" in checks
    assert "supply_chain" in checks


def test_basic_assessment():
    """Test basic assessment."""
    assessor = AIComplianceAssessor()

    system_info = {
        "name": "Test AI",
        "type": "llm",
        "use_case": "customer_support",
        "data_types": ["personal"]
    }

    result = assessor.assess(system_info=system_info)

    assert result is not None
    assert result.assessment_id is not None
    assert result.overall_score >= 0
    assert result.overall_score <= 100
    assert result.overall_risk is not None


def test_gdpr_assessment():
    """Test GDPR framework assessment."""
    assessor = AIComplianceAssessor()

    system_info = {
        "name": "Test AI",
        "type": "llm",
        "use_case": "customer_support",
        "data_types": ["personal", "pii"]
    }

    result = assessor.assess(
        system_info=system_info,
        frameworks=["gdpr"]
    )

    assert len(result.frameworks) == 1
    assert result.frameworks[0].framework_name == "GDPR"
    assert len(result.frameworks[0].findings) > 0


def test_eu_ai_act_high_risk():
    """Test EU AI Act classification of high-risk system."""
    assessor = AIComplianceAssessor()

    system_info = {
        "name": "Hiring AI",
        "type": "predictive",
        "use_case": "hiring",
        "data_types": ["personal"]
    }

    result = assessor.assess(
        system_info=system_info,
        frameworks=["eu_ai_act"]
    )

    assert len(result.frameworks) == 1
    # High-risk systems should have findings
    assert len(result.frameworks[0].findings) > 0


def test_owasp_llm_assessment():
    """Test OWASP LLM security assessment."""
    assessor = AIComplianceAssessor()

    system_info = {
        "name": "Test LLM",
        "type": "llm",
        "use_case": "customer_support",
        "data_types": []
    }

    result = assessor.assess(
        system_info=system_info,
        security_checks=["owasp_llm"]
    )

    assert len(result.security) == 1
    assert result.security[0].category == "OWASP LLM Security"
    assert len(result.security[0].findings) > 0


def test_healthcare_hipaa():
    """Test HIPAA assessment for healthcare AI."""
    assessor = AIComplianceAssessor()

    system_info = {
        "name": "Medical AI",
        "type": "predictive",
        "use_case": "health_diagnosis",
        "data_types": ["health", "phi"]
    }

    result = assessor.assess(
        system_info=system_info,
        frameworks=["hipaa"]
    )

    assert len(result.frameworks) == 1
    # Healthcare AI with PHI should have findings
    assert len(result.frameworks[0].findings) > 0
    assert result.frameworks[0].overall_status.value != "not_applicable"


def test_assessment_summary():
    """Test assessment summary generation."""
    assessor = AIComplianceAssessor()

    system_info = {
        "name": "Test AI",
        "type": "llm",
        "use_case": "customer_support",
        "data_types": ["personal"]
    }

    result = assessor.assess(system_info=system_info)
    summary = result.summary()

    assert "ASSESSMENT" in summary
    assert result.system_info.name in summary
    assert str(result.overall_score) in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
