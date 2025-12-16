# Architecture Documentation

## Overview

The AI Compliance and Security Assessor is designed as a modular, extensible system for assessing AI systems against compliance frameworks and security standards.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User Interfaces                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │   CLI    │  │ REST API │  │  Python API          │  │
│  └──────────┘  └──────────┘  └──────────────────────┘  │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│              Assessment Engine                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │       AIComplianceAssessor (Orchestrator)        │  │
│  └──────────────────────────────────────────────────┘  │
└──────────┬────────────────────────────────┬─────────────┘
           │                                │
     ┌─────▼──────┐                  ┌─────▼──────┐
     │ Frameworks │                  │  Security  │
     │ Assessment │                  │   Checks   │
     └─────┬──────┘                  └─────┬──────┘
           │                                │
    ┌──────┴───────┐              ┌────────┴────────┐
    │              │              │                 │
┌───▼───┐  ┌───────▼─────┐  ┌────▼────┐  ┌────────▼────┐
│ GDPR  │  │  EU AI Act  │  │  OWASP  │  │ Adversarial │
└───────┘  └─────────────┘  └─────────┘  └─────────────┘
┌───────┐  ┌─────────────┐  ┌─────────┐  ┌─────────────┐
│ NIST  │  │  ISO 42001  │  │ Privacy │  │    Model    │
└───────┘  └─────────────┘  └─────────┘  └─────────────┘
┌───────┐                   ┌─────────┐
│ HIPAA │                   │  Supply │
└───────┘                   │  Chain  │
                            └─────────┘
           │                                │
           │                                │
     ┌─────▼────────────────────────────────▼─────┐
     │         Assessment Result Model            │
     └────────────────┬───────────────────────────┘
                      │
              ┌───────▼────────┐
              │ Report         │
              │ Generator      │
              └───────┬────────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
    ┌────▼───┐  ┌────▼────┐  ┌───▼────┐
    │  JSON  │  │Markdown │  │  HTML  │
    └────────┘  └─────────┘  └────────┘
```

## Core Components

### 1. Assessment Engine (`src/assessor/`)

**AIComplianceAssessor** - Main orchestrator
- Coordinates framework and security assessments
- Aggregates results
- Calculates overall scores and risk levels

**Models** (`models.py`)
- `AISystemInfo` - Input system information
- `AssessmentResult` - Complete assessment output
- `FrameworkAssessment` - Framework-specific results
- `SecurityAssessment` - Security check results
- `Finding` - Individual finding/issue

### 2. Compliance Frameworks (`src/frameworks/`)

Each framework implements the `ComplianceFramework` base class:

- **GDPRFramework** - GDPR compliance
- **EUAIActFramework** - EU AI Act risk classification
- **NISTFramework** - NIST AI RMF
- **ISO42001Framework** - ISO/IEC 42001
- **HIPAAFramework** - HIPAA for healthcare AI

**Interface:**
```python
class ComplianceFramework(ABC):
    def assess(self, system_info: AISystemInfo) -> FrameworkAssessment
    def get_requirements(self) -> List[str]
```

### 3. Security Checks (`src/security/`)

Each security check implements the `SecurityChecker` base class:

- **OWASPLLMChecker** - OWASP LLM Top 10
- **AdversarialChecker** - Adversarial robustness
- **DataPrivacyChecker** - Data privacy controls
- **ModelSecurityChecker** - Model security
- **SupplyChainChecker** - Supply chain security

**Interface:**
```python
class SecurityChecker(ABC):
    def assess(self, system_info: AISystemInfo) -> SecurityAssessment
    def get_checks(self) -> List[str]
```

### 4. Report Generation (`src/reports/`)

**ReportGenerator**
- Generates reports in multiple formats
- Supports JSON, Markdown, and HTML
- Extensible for additional formats

### 5. Interfaces

**CLI** (`src/cli.py`)
- Built with Click
- Rich terminal output
- Commands: assess, list-frameworks, list-checks

**REST API** (`src/api/server.py`)
- Built with FastAPI
- OpenAPI documentation
- Endpoints for assessment, listing, and reporting

**Python API**
- Direct import and usage
- Programmatic access to all features

## Data Flow

1. **Input**: User provides AI system information via CLI, API, or Python
2. **Validation**: System info is validated and converted to `AISystemInfo`
3. **Assessment**:
   - Selected frameworks are run in parallel (conceptually)
   - Selected security checks are run in parallel
   - Each returns findings and scores
4. **Aggregation**: Results are combined into `AssessmentResult`
5. **Scoring**: Overall score and risk level are calculated
6. **Output**: Results are returned and optionally formatted as reports

## Extensibility

### Adding a New Framework

1. Create new file in `src/frameworks/`
2. Inherit from `ComplianceFramework`
3. Implement `assess()` and `get_requirements()`
4. Register in `src/frameworks/__init__.py`
5. Add to `AIComplianceAssessor._load_frameworks()`

Example:
```python
class NewFramework(ComplianceFramework):
    def __init__(self):
        super().__init__("Framework Name", "1.0")

    def assess(self, system_info: AISystemInfo) -> FrameworkAssessment:
        # Implementation
        pass

    def get_requirements(self) -> List[str]:
        return ["Requirement 1", "Requirement 2"]
```

### Adding a New Security Check

1. Create new file in `src/security/`
2. Inherit from `SecurityChecker`
3. Implement `assess()` and `get_checks()`
4. Register in `src/security/__init__.py`
5. Add to `AIComplianceAssessor._load_security_checks()`

### Adding a Report Format

1. Add method to `ReportGenerator`
2. Implement format generation logic
3. Update CLI and API to support new format

## Design Principles

1. **Modularity**: Each framework and security check is independent
2. **Extensibility**: Easy to add new frameworks and checks
3. **Consistency**: Common interfaces and data models
4. **Separation of Concerns**: Clear boundaries between components
5. **Testability**: Each component can be tested independently
6. **Usability**: Multiple interfaces for different use cases

## Dependencies

- **pydantic**: Data validation and modeling
- **click**: CLI framework
- **rich**: Terminal formatting
- **fastapi**: REST API framework
- **uvicorn**: ASGI server

## Performance Considerations

- Framework assessments are independent (can be parallelized)
- Security checks are independent (can be parallelized)
- Large-scale assessments can generate substantial findings
- Report generation is on-demand

## Security Considerations

- No external API calls (runs locally)
- No data collection or transmission
- Input validation via Pydantic models
- No execution of untrusted code
