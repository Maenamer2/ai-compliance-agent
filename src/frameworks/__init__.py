"""Compliance framework implementations."""

try:
    from src.frameworks.gdpr import GDPRFramework
    from src.frameworks.eu_ai_act import EUAIActFramework
    from src.frameworks.nist import NISTFramework
    from src.frameworks.iso42001 import ISO42001Framework
    from src.frameworks.hipaa import HIPAAFramework
    from src.frameworks.base import ComplianceFramework
except (ImportError, ModuleNotFoundError):
    from .gdpr import GDPRFramework
    from .eu_ai_act import EUAIActFramework
    from .nist import NISTFramework
    from .iso42001 import ISO42001Framework
    from .hipaa import HIPAAFramework
    from .base import ComplianceFramework

__all__ = [
    "ComplianceFramework",
    "GDPRFramework",
    "EUAIActFramework",
    "NISTFramework",
    "ISO42001Framework",
    "HIPAAFramework"
]
