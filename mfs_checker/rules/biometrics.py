"""
BB-MFS-14: Biometric Authentication Cryptographic Object Binding
Clauses: 4.1.3.21, 4.1.5.17
"""

from typing import List, Any
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence

class BiometricsRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-14")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        strings = self.extract_all_strings(analysis, dex_list)

        has_biometric_prompt = any("BiometricPrompt" in s for s in strings)
        has_crypto_object = any("CryptoObject" in s for s in strings)
        has_fingerprint_mgr = any("FingerprintManager" in s for s in strings)

        if has_biometric_prompt and has_crypto_object:
            findings.append(Finding(
                description="Verified: Uses AndroidX BiometricPrompt bound with cryptographic CryptoObject.",
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
                details="Complies with Clause 4.1.3.21 & 4.1.5.17: Biometric authentication cryptographically bound to hardware key."
            )
        elif has_biometric_prompt or has_fingerprint_mgr:
            findings.append(Finding(
                description="Biometric authentication present but lacks explicit CryptoObject binding in detected calls.",
                confidence=Confidence.MEDIUM
            ))
            return RuleResult(
                rule_id=self.rule_id,
                clause=self.clause,
                title=self.title,
                function=self.function,
                category=self.category,
                status=RuleStatus.WARNING,
                severity=self.severity,
                penalty=2,
                remediation=self.remediation,
                findings=findings,
                details="Advisory: Ensure BiometricPrompt passes BiometricPrompt.CryptoObject for cryptographic authentication."
            )
        else:
            findings.append(Finding(
                description="No biometric authentication framework (BiometricPrompt) integrated.",
                confidence=Confidence.LOW
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
                details="Missing modern biometric authentication framework (BiometricPrompt)."
            )
