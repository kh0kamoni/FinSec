"""
BB-MFS-12: Root, Jailbreak & Execution Environment Integrity Detection
Clauses: 4.1.4.4, 5.1.2.19
"""

from typing import List, Any
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence

class RootDetectionRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-12")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        strings = self.extract_all_strings(analysis, dex_list)

        root_indicators = [
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/failsafe/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
            "which su",
            "test-keys",
            "Superuser.apk",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.topjohnwu.magisk",
            "rootbeer",
            "RootBeer",
            "isRooted",
            "checkRootMethod"
        ]

        found_indicators = []
        for s in strings:
            for ind in root_indicators:
                if ind.lower() in s.lower() and ind not in found_indicators:
                    found_indicators.append(ind)

        if found_indicators:
            for ind in found_indicators[:5]:
                findings.append(Finding(
                    description=f"Verified environment integrity check: detects '{ind}'",
                    confidence=Confidence.HIGH,
                    code_snippet=ind
                ))
            return RuleResult(
                rule_id=self.rule_id,
                clause=self.clause,
                title=self.title,
                function=self.function,
                category=self.category,
                status=RuleStatus.PASSED,
                severity=self.severity,
                penalty=0,
                remediation=self.remediation,
                findings=findings,
                details=f"Complies with Clause 4.1.4.4 & 5.1.2.19: Found {len(found_indicators)} root/integrity detection indicators."
            )
        else:
            findings.append(Finding(
                description="No root/jailbreak detection mechanisms identified in application bytecode.",
                confidence=Confidence.HIGH
            ))
            return RuleResult(
                rule_id=self.rule_id,
                clause=self.clause,
                title=self.title,
                function=self.function,
                category=self.category,
                status=RuleStatus.FAILED,
                severity=self.severity,
                penalty=self.penalty,
                remediation=self.remediation,
                findings=findings,
                details="Violation of Clause 4.1.4.4 & 5.1.2.19: Missing root/jailbreak and execution environment integrity validation."
            )
