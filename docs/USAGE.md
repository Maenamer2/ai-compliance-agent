# AI Compliance Assessor - Usage Guide

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ai-compliance-agent.git
cd ai-compliance-agent

# Install dependencies
pip install -r requirements.txt

# Or install in development mode
pip install -e .
```

## Quick Start

### Python API

```python
from src.assessor import AIComplianceAssessor

# Initialize assessor
assessor = AIComplianceAssessor()

# Define your AI system
system_info = {
    "name": "My AI Assistant",
    "type": "llm",
    "use_case": "customer_support",
    "data_types": ["personal", "conversations"]
}

# Run assessment
result = assessor.assess(
    system_info=system_info,
    frameworks=["gdpr", "eu_ai_act"],
    security_checks=["owasp_llm", "data_privacy"]
)

# View summary
print(result.summary())

# Generate report
from src.reports import ReportGenerator
generator = ReportGenerator()
generator.generate_markdown(result, "report.md")
```

### Command Line Interface

```bash
# List available frameworks
python -m src.cli list-frameworks

# List available security checks
python -m src.cli list-checks

# Run assessment
python -m src.cli assess \
  --name "My AI System" \
  --type llm \
  --use-case customer_support \
  -f gdpr -f eu_ai_act \
  -s owasp_llm \
  --output report.md \
  --format markdown

# Use configuration file
python -m src.cli assess --config examples/config_example.json --output report.json --format json
```

### REST API

```bash
# Start the API server
python -m src.api.server

# Or with uvicorn
uvicorn src.api.server:app --reload
```

API endpoints:
- `GET /` - API information
- `POST /assess` - Run assessment
- `GET /frameworks` - List frameworks
- `GET /security-checks` - List security checks
- `POST /report/{format}` - Generate report

Example API request:

```bash
curl -X POST "http://localhost:8000/assess" \
  -H "Content-Type: application/json" \
  -d '{
    "system_info": {
      "name": "Test AI",
      "type": "llm",
      "use_case": "customer_support",
      "data_types": ["personal"]
    },
    "frameworks": ["gdpr", "nist"],
    "security_checks": ["owasp_llm"]
  }'
```

## System Information Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | AI system name |
| type | string | Yes | AI type: llm, vision, multimodal, predictive, generative, recommendation |
| use_case | string | Yes | Use case: customer_support, medical, hiring, credit_scoring, etc. |
| description | string | No | System description |
| data_types | list | No | Data types processed: personal, pii, health, financial, biometric |
| user_base | string | No | Target user base |
| deployment_region | string | No | Deployment regions (e.g., "US, EU") |
| model_info | dict | No | Model details |
| architecture | dict | No | Architecture details |

## Available Frameworks

### GDPR (General Data Protection Regulation)
Assesses compliance with EU data protection requirements.

### EU AI Act
Risk-based assessment according to EU AI regulation.

### NIST AI RMF
Assessment against NIST AI Risk Management Framework.

### ISO/IEC 42001
AI Management System compliance.

### HIPAA
Healthcare privacy and security compliance.

## Available Security Checks

### OWASP LLM Top 10
Checks for common LLM vulnerabilities:
- Prompt injection
- Insecure output handling
- Training data poisoning
- Model denial of service
- Supply chain vulnerabilities
- Sensitive information disclosure
- Insecure plugin design
- Excessive agency
- Overreliance
- Model theft

### Adversarial Robustness
Tests resistance to adversarial attacks:
- Evasion attacks
- Model inversion
- Membership inference
- Backdoor attacks
- Data poisoning

### Data Privacy
Assesses data privacy protections:
- PII detection and handling
- Data minimization
- Encryption
- Access controls
- Data retention

### Model Security
Evaluates model-specific security:
- Model access controls
- Model integrity
- Secure deployment
- Model monitoring

### Supply Chain Security
Checks supply chain risks:
- Dependency vulnerabilities
- Third-party model verification
- Dataset provenance
- Library vulnerabilities

## Report Formats

### JSON
Machine-readable format with complete assessment data.

```python
generator.generate_json(result, "report.json")
```

### Markdown
Human-readable format suitable for documentation.

```python
generator.generate_markdown(result, "report.md")
```

### HTML
Styled HTML report for web viewing.

```python
generator.generate_html(result, "report.html")
```

## Examples

See the `examples/` directory for complete examples:

- `basic_assessment.py` - Basic assessment example
- `healthcare_ai.py` - Healthcare AI assessment
- `config_example.json` - Example configuration file

## Risk Levels

- **Critical** - Immediate attention required
- **High** - Important security/compliance issue
- **Medium** - Should be addressed
- **Low** - Minor issue
- **Minimal** - Informational

## Compliance Status

- **Compliant** - Meets requirements
- **Partial** - Partially compliant
- **Non-Compliant** - Does not meet requirements
- **Not Applicable** - Requirements don't apply
- **Unknown** - Cannot determine status

## Best Practices

1. **Regular Assessments**: Run assessments regularly, especially after system updates
2. **Comprehensive Coverage**: Use all relevant frameworks and security checks
3. **Document Results**: Save reports for compliance evidence
4. **Address Critical Findings**: Prioritize critical and high-severity findings
5. **Track Progress**: Re-assess after implementing remediations
6. **Integrate CI/CD**: Automate assessments in your deployment pipeline
