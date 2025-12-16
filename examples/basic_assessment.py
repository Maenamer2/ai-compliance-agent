"""Basic example of using the AI compliance assessor."""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.assessor import AIComplianceAssessor
from src.reports import ReportGenerator


def main():
    """Run a basic compliance assessment."""
    print("AI Compliance and Security Assessor - Basic Example\n")

    # Define AI system to assess
    system_info = {
        "name": "Customer Support Chatbot",
        "type": "llm",
        "use_case": "customer_support",
        "description": "An LLM-based chatbot that assists customers with product questions",
        "data_types": ["personal", "conversations"],
        "user_base": "global",
        "deployment_region": "US, EU"
    }

    # Initialize assessor
    print("Initializing assessor...")
    assessor = AIComplianceAssessor()

    # List available frameworks and checks
    print(f"\nAvailable frameworks: {', '.join(assessor.list_frameworks())}")
    print(f"Available security checks: {', '.join(assessor.list_security_checks())}")

    # Run assessment
    print(f"\nAssessing: {system_info['name']}...")
    result = assessor.assess(
        system_info=system_info,
        frameworks=["gdpr", "eu_ai_act", "nist"],
        security_checks=["owasp_llm", "data_privacy"]
    )

    # Display summary
    print("\n" + "="*60)
    print(result.summary())
    print("="*60)

    # Generate reports
    print("\nGenerating reports...")
    generator = ReportGenerator()

    # Markdown report
    markdown = generator.generate_markdown(result, "reports/assessment_report.md")
    print("✓ Markdown report: reports/assessment_report.md")

    # JSON report
    json_report = generator.generate_json(result, "reports/assessment_report.json")
    print("✓ JSON report: reports/assessment_report.json")

    # HTML report
    html = generator.generate_html(result, "reports/assessment_report.html")
    print("✓ HTML report: reports/assessment_report.html")

    # Show some findings
    print("\n" + "="*60)
    print("SAMPLE FINDINGS:")
    print("="*60)

    if result.frameworks:
        fw = result.frameworks[0]
        print(f"\n{fw.framework_name} - Top Finding:")
        if fw.findings:
            finding = fw.findings[0]
            print(f"  Title: {finding.title}")
            print(f"  Severity: {finding.severity.value}")
            print(f"  Recommendation: {finding.recommendation[:100]}...")

    if result.security:
        sec = result.security[0]
        print(f"\n{sec.category} - Top Finding:")
        if sec.findings:
            finding = sec.findings[0]
            print(f"  Title: {finding.title}")
            print(f"  Severity: {finding.severity.value}")
            print(f"  Recommendation: {finding.recommendation[:100]}...")

    print("\n✓ Assessment complete!")


if __name__ == "__main__":
    # Create reports directory
    Path("reports").mkdir(exist_ok=True)
    main()
