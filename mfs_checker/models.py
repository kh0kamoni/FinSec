"""
Data models for Bangladesh Bank Cybersecurity Framework Compliance Auditor.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Optional, Any
import json

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class RuleStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class ComplianceTier(str, Enum):
    TIER_1_COMPLIANT = "Tier 1: Compliant (Eligible for Production)"
    TIER_2_CONDITIONAL = "Tier 2: Substantially Compliant (Remediation Required)"
    TIER_3_HIGH_RISK = "Tier 3: High Risk (Regulatory Action & Escalation Required)"

@dataclass
class Finding:
    """Individual code or manifest evidence of compliance/violation."""
    description: str
    confidence: Confidence = Confidence.HIGH
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "confidence": self.confidence.value,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "metadata": self.metadata
        }

@dataclass
class RuleResult:
    """Evaluation result for a specific Bangladesh Bank regulatory clause."""
    rule_id: str
    clause: str
    title: str
    function: str
    category: str
    status: RuleStatus
    severity: Severity
    penalty: int
    remediation: str
    findings: List[Finding] = field(default_factory=list)
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "clause": self.clause,
            "title": self.title,
            "function": self.function,
            "category": self.category,
            "status": self.status.value,
            "severity": self.severity.value,
            "penalty": self.penalty,
            "remediation": self.remediation,
            "details": self.details,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings]
        }

@dataclass
class ComplianceScorecard:
    """Overall compliance evaluation report for an audited mobile application."""
    app_name: str
    package_name: str
    version_name: str
    version_code: str
    sha256_hash: str
    apk_size_mb: float
    maturity_score: float
    tier: ComplianceTier
    total_rules: int
    passed_rules: int
    failed_rules: int
    warning_rules: int
    critical_violations: int
    rule_results: List[RuleResult] = field(default_factory=list)
    ml_risk_prediction: Optional[Dict[str, Any]] = None
    execution_time_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "app_name": self.app_name,
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "sha256_hash": self.sha256_hash,
            "apk_size_mb": round(self.apk_size_mb, 2),
            "maturity_score": round(self.maturity_score, 1),
            "tier": self.tier.value,
            "summary": {
                "total_rules": self.total_rules,
                "passed_rules": self.passed_rules,
                "failed_rules": self.failed_rules,
                "warning_rules": self.warning_rules,
                "critical_violations": self.critical_violations
            },
            "rule_results": [r.to_dict() for r in self.rule_results],
            "ml_risk_prediction": self.ml_risk_prediction,
            "execution_time_seconds": round(self.execution_time_seconds, 2)
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
