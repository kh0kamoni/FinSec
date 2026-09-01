"""
BB-MFS-05: Secure Hardware Cryptographic Key Storage
Clauses: 4.1.5.18, 4.1.5.7
"""

from typing import List, Any
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence

class KeystoreSecurityRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-05")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        strings = self.extract_all_strings(analysis, dex_list)

        # AndroidKeyStore indicators
        has_android_keystore = False
        for s in strings:
            if "AndroidKeyStore" in s or "AndroidKeyStoreProvider" in s or "KeyGenParameterSpec" in s:
                has_android_keystore = True
                break

        # Insecure key handling indicators (e.g. hardcoded keys or storing raw keys)
        insecure_key_indicators = [
            "raw_key",
            "encryption_key",
            "aes_key",
            "private_key_pem",
            "secret_key"
        ]
        suspicious_key_strings = []
        for s in strings:
            if any(k in s.lower() for k in insecure_key_indicators) and len(s) in [16, 24, 32, 64, 128]:
                # Possible hardcoded literal key
                if self.calculate_entropy(s) > 3.5:
                    suspicious_key_strings.append(s)

        if suspicious_key_strings and not has_android_keystore:
            for k in suspicious_key_strings[:3]:
                findings.append(Finding(
                    description=f"Potential hardcoded cryptographic key literal detected (entropy: {self.calculate_entropy(k):.2f}).",
                    confidence=Confidence.HIGH,
                    code_snippet=k[:8] + "..." + k[-4:]
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
                details="Violation of Clause 4.1.5.18: Hardcoded cryptographic keys detected without AndroidKeyStore."
            )
        elif has_android_keystore:
            findings.append(Finding(
                description="Verified hardware-backed AndroidKeyStore integration for cryptographic key management.",
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
                details="Cryptographic key management complies with Clause 4.1.5.18."
            )
        else:
            findings.append(Finding(
                description="AndroidKeyStore not explicitly detected; verify if keys are stored in backend HSM.",
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
                penalty=5,
                remediation=self.remediation,
                findings=findings,
                details="No AndroidKeyStore usage found in client binary."
            )
