"""Core assessment engine for AI compliance and security."""

try:
    from src.assessor.engine import AIComplianceAssessor, AssessmentResult
except (ImportError, ModuleNotFoundError):
    from .engine import AIComplianceAssessor, AssessmentResult

__all__ = ["AIComplianceAssessor", "AssessmentResult"]
