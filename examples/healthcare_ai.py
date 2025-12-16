"""Example: Healthcare AI system assessment."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.assessor import AIComplianceAssessor
from src.reports import ReportGenerator


def main():
    """Assess a healthcare AI system."""
    print("Healthcare AI Compliance Assessment Example\n")

    # Healthcare AI system
    system_info = {
        "name": "Medical Imaging Diagnostic Assistant",
        "type": "vision",
        "use_case": "health_diagnosis",
        "description": "AI system for analyzing medical images and assisting with diagnoses",
        "data_types": ["health", "medical", "pii"],
        "user_base": "healthcare_providers",
        "deployment_region": "US",
        "model_info": {
            "type": "computer_vision",
            "training": "supervised",
            "data_size": "100k_images"
        }
    }

    assessor = AIComplianceAssessor()

    print(f"Assessing: {system_info['name']}...")
    print("This is a high-risk healthcare AI system.\n")

    # Assess with healthcare-relevant frameworks
    result = assessor.assess(
        system_info=system_info,
        frameworks=["hipaa", "gdpr", "nist", "eu_ai_act"],
        security_checks=["adversarial", "data_privacy", "model_security"]
    )

    # Display results
    print(result.summary())

    # Generate detailed report
    generator = ReportGenerator()
    generator.generate_markdown(result, "reports/healthcare_ai_assessment.md")
    generator.generate_html(result, "reports/healthcare_ai_assessment.html")

    print("\n✓ Healthcare AI assessment complete!")
    print("✓ Reports generated in reports/ directory")

    # Highlight critical findings
    print("\n" + "="*60)
    print("CRITICAL FINDINGS:")
    print("="*60)

    for fw in result.frameworks:
        critical = [f for f in fw.findings if f.severity.value == "critical"]
        if critical:
            print(f"\n{fw.framework_name}:")
            for finding in critical:
                print(f"  • {finding.title}")

    for sec in result.security:
        critical = [f for f in sec.findings if f.severity.value == "critical"]
        if critical:
            print(f"\n{sec.category}:")
            for finding in critical:
                print(f"  • {finding.title}")


if __name__ == "__main__":
    Path("reports").mkdir(exist_ok=True)
    main()
