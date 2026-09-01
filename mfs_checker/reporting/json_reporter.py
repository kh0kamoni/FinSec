"""
JSON Reporter for Bangladesh Bank Compliance Audits.
"""

from typing import Optional
from mfs_checker.models import ComplianceScorecard

def generate_json_report(scorecard: ComplianceScorecard, file_path: Optional[str] = None) -> str:
    """Generate structured JSON report and optionally save to file."""
    json_data = scorecard.to_json(indent=2)
    if file_path:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(json_data)
    return json_data
