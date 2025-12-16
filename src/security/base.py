"""Base class for security checkers."""

from abc import ABC, abstractmethod
from typing import List
from ..assessor.models import AISystemInfo, SecurityAssessment, Finding


class SecurityChecker(ABC):
    """Base class for security assessment modules."""

    def __init__(self, category: str):
        """Initialize the security checker."""
        self.category = category

    @abstractmethod
    def assess(self, system_info: AISystemInfo) -> SecurityAssessment:
        """
        Assess AI system security.

        Args:
            system_info: Information about the AI system

        Returns:
            SecurityAssessment with findings
        """
        pass

    @abstractmethod
    def get_checks(self) -> List[str]:
        """Get list of security checks performed."""
        pass
