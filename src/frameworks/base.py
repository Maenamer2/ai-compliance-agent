"""Base class for compliance frameworks."""

from abc import ABC, abstractmethod
from typing import List
from ..assessor.models import AISystemInfo, FrameworkAssessment, Finding


class ComplianceFramework(ABC):
    """Base class for compliance framework implementations."""

    def __init__(self, name: str, version: str):
        """Initialize the framework."""
        self.name = name
        self.version = version

    @abstractmethod
    def assess(self, system_info: AISystemInfo) -> FrameworkAssessment:
        """
        Assess an AI system against this compliance framework.

        Args:
            system_info: Information about the AI system

        Returns:
            FrameworkAssessment with findings
        """
        pass

    @abstractmethod
    def get_requirements(self) -> List[str]:
        """Get list of compliance requirements."""
        pass
