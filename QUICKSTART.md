# Running the AI Compliance Assessor

This guide helps you run the assessor on Windows, macOS, or Linux.

## Installation Methods

### Method 1: Install in Development Mode (Recommended)

This makes the package importable from anywhere:

```bash
# From the project root directory
pip install -e .
```

After this, you can run:
```bash
python -m src.cli assess --help
python -m src.api.server
```

### Method 2: Use Standalone Scripts (Quick Start)

If you don't want to install the package, use these scripts:

```bash
# Run CLI
python run_cli.py list-frameworks
python run_cli.py assess --name "Test" --type llm --use-case customer_support

# Run API Server
python run_api.py
```

## Quick Start Guide

### 1. Install Dependencies

```bash
# Create virtual environment (optional but recommended)
python -m venv venv

# Activate it:
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install FastAPI and Uvicorn for API (optional)
pip install fastapi uvicorn
```

### 2. Run Your First Assessment

**Option A: Python Script**
```bash
python examples/basic_assessment.py
```

**Option B: Standalone CLI**
```bash
python run_cli.py assess --name "My AI" --type llm --use-case customer_support -f gdpr -s owasp_llm
```

**Option C: Installed CLI** (if you ran `pip install -e .`)
```bash
python -m src.cli assess --name "My AI" --type llm --use-case customer_support
```

### 3. Start API Server

**Option A: Standalone Script**
```bash
python run_api.py
```

**Option B: After Installing Package**
```bash
python -m src.api.server
# or
uvicorn src.api.server:app --reload
```

Then visit:
- API Docs: http://localhost:8000/docs
- API Root: http://localhost:8000

### 4. View Reports

After running an assessment, check the `reports/` directory:
- `assessment_report.md` - Human-readable Markdown
- `assessment_report.json` - Machine-readable JSON
- `assessment_report.html` - Web-viewable HTML

## Troubleshooting

### "ModuleNotFoundError: No module named 'src.xxx'"

**Solution 1**: Install the package
```bash
pip install -e .
```

**Solution 2**: Use standalone scripts
```bash
python run_cli.py
python run_api.py
```

### "No module named 'fastapi'" or "No module named 'uvicorn'"

```bash
pip install fastapi uvicorn
```

### "No module named 'click'" or "No module named 'rich'"

```bash
pip install -r requirements.txt
```

## Windows-Specific Notes

On Windows, use backslashes or forward slashes for paths:
```bash
python examples\basic_assessment.py
# or
python examples/basic_assessment.py
```

Activate virtual environment:
```bash
venv\Scripts\activate
```

## Examples

```bash
# List available frameworks
python run_cli.py list-frameworks

# List security checks
python run_cli.py list-checks

# Full assessment with multiple frameworks
python run_cli.py assess \
  --name "Healthcare AI" \
  --type vision \
  --use-case health_diagnosis \
  -f gdpr -f hipaa -f nist \
  -s adversarial -s data_privacy \
  --output my_report.md

# Run healthcare example
python examples/healthcare_ai.py

# Use config file
python run_cli.py assess --config examples/config_example.json --output report.html --format html
```

## Using the API

```bash
# Start server
python run_api.py

# In another terminal, test it:
curl http://localhost:8000/

# Get frameworks
curl http://localhost:8000/frameworks

# Run assessment
curl -X POST http://localhost:8000/assess \
  -H "Content-Type: application/json" \
  -d '{
    "system_info": {
      "name": "Test AI",
      "type": "llm",
      "use_case": "customer_support",
      "data_types": ["personal"]
    },
    "frameworks": ["gdpr"],
    "security_checks": ["owasp_llm"]
  }'
```

Visit http://localhost:8000/docs for interactive API documentation!
