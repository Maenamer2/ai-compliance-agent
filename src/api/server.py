"""FastAPI server for AI compliance assessor."""

import sys
from typing import List, Optional, Dict, Any

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
except ImportError:
    print("Please install FastAPI: pip install fastapi uvicorn")
    sys.exit(1)

from src.assessor import AIComplianceAssessor
from src.assessor.models import AssessmentResult
from src.reports import ReportGenerator


app = FastAPI(
    title="AI Compliance and Security Assessor API",
    description="API for assessing AI systems for compliance and security",
    version="0.1.0"
)

# Initialize assessor
assessor = AIComplianceAssessor()
report_generator = ReportGenerator()


class AssessmentRequest(BaseModel):
    """Request model for assessment."""
    system_info: Dict[str, Any]
    frameworks: Optional[List[str]] = None
    security_checks: Optional[List[str]] = None


class AssessmentResponse(BaseModel):
    """Response model for assessment."""
    assessment_id: str
    overall_score: float
    overall_risk: str
    total_findings: int
    critical_findings: int
    high_findings: int
    result: Dict[str, Any]


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "AI Compliance and Security Assessor API",
        "version": "0.1.0",
        "endpoints": {
            "assess": "/assess",
            "frameworks": "/frameworks",
            "security_checks": "/security-checks",
            "report": "/report/{assessment_id}"
        }
    }


@app.post("/assess", response_model=AssessmentResponse)
async def assess_system(request: AssessmentRequest):
    """
    Assess an AI system for compliance and security.

    Args:
        request: Assessment request with system information

    Returns:
        Assessment results
    """
    try:
        result = assessor.assess(
            system_info=request.system_info,
            frameworks=request.frameworks,
            security_checks=request.security_checks
        )

        return AssessmentResponse(
            assessment_id=result.assessment_id,
            overall_score=result.overall_score,
            overall_risk=result.overall_risk.value,
            total_findings=result.total_findings,
            critical_findings=result.critical_findings,
            high_findings=result.high_findings,
            result=result.model_dump(mode='json')
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/frameworks")
async def list_frameworks():
    """List available compliance frameworks."""
    frameworks = assessor.list_frameworks()
    return {
        "frameworks": frameworks,
        "count": len(frameworks)
    }


@app.get("/security-checks")
async def list_security_checks():
    """List available security checks."""
    checks = assessor.list_security_checks()
    return {
        "security_checks": checks,
        "count": len(checks)
    }


@app.post("/report/{format}")
async def generate_report(format: str, result_data: Dict[str, Any]):
    """
    Generate a report in specified format.

    Args:
        format: Report format (json, markdown, html)
        result_data: Assessment result data

    Returns:
        Generated report
    """
    try:
        # Convert dict to AssessmentResult
        result = AssessmentResult(**result_data)

        if format == "json":
            content = report_generator.generate_json(result)
            return JSONResponse(content={"report": content})
        elif format == "markdown":
            content = report_generator.generate_markdown(result)
            return {"report": content}
        elif format == "html":
            content = report_generator.generate_html(result)
            return {"report": content}
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
