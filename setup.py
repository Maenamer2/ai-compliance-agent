"""Setup configuration for AI Compliance Assessor."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme = Path("README.md").read_text()

setup(
    name="ai-compliance-agent",
    version="0.1.0",
    description="AI agent that assesses other AI systems for compliance and security",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="AI Compliance Team",
    python_requires=">=3.8",
    packages=find_packages(),
    install_requires=[
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
        "requests>=2.31.0",
        "python-dateutil>=2.8.2",
        "jinja2>=3.1.0",
        "markdown>=3.5.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "fastapi>=0.104.0",
        "uvicorn>=0.24.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "security": [
            "safety>=3.0.0",
            "bandit>=1.7.0",
        ],
        "ai": [
            "anthropic>=0.25.0",
            "openai>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ai-compliance=src.cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
