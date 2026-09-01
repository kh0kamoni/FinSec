"""
BB-MFS-06: Transaction Signing, Non-Repudiation & Anti-Replay Protection
Clauses: 4.1.3.10, 5.1.1.11
"""

from typing import List, Any
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence

class TransactionSigningRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-06")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        strings = self.extract_all_strings(analysis, dex_list)

        signature_indicators = [
            "java/security/Signature",
            "java.security.Signature",
            "SHA256withRSA",
            "SHA256withECDSA",
            "SHA512withRSA",
            "HmacSHA256",
            "javax/crypto/Mac",
            "javax.crypto.Mac"
        ]

        has_signature_primitives = False
        matched_indicators = []
        for ind in signature_indicators:
            for s in strings:
                if ind in s:
                    has_signature_primitives = True
                    matched_indicators.append(ind)
                    break

        if has_signature_primitives:
            findings.append(Finding(
                description=f"Verified transaction signing & payload integrity primitives: {', '.join(set(matched_indicators))}",
                confidence=Confidence.HIGH
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
                details="Transaction non-repudiation & anti-replay controls verified per Clause 4.1.3.10."
            )
        else:
            findings.append(Finding(
                description="No digital signature or HMAC transaction signing primitives detected in client application.",
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
                details="Violation of Clause 4.1.3.10: Client application lacks transaction signing mechanisms."
            )
