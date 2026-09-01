"""
BB-MFS-07: Cryptographically Secure Pseudo-Random Number Generation (PRNG)
Clauses: 4.1.5.18, 4.1.5.19
"""

from typing import List, Any
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence

class CryptographicRandomnessRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-07")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        strings = self.extract_all_strings(analysis, dex_list)

        has_secure_random = False
        has_insecure_random = False

        secure_prng_indicators = [
            "java/security/SecureRandom",
            "java.security.SecureRandom",
            "SecureRandom"
        ]

        insecure_prng_indicators = [
            "Ljava/util/Random;->nextInt",
            "Ljava/util/Random;->nextBytes",
            "java.util.Random",
            "Math.random"
        ]

        for s in strings:
            if any(ind in s for ind in secure_prng_indicators):
                has_secure_random = True
                break

        for s in strings:
            if any(ind in s for ind in insecure_prng_indicators):
                has_insecure_random = True
                break

        if has_secure_random:
            findings.append(Finding(
                description="Verified java.security.SecureRandom usage for cryptographically secure randomness.",
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
                details="Complies with Clause 4.1.5.18: Secure pseudo-random number generator utilized."
            )
        elif has_insecure_random:
            findings.append(Finding(
                description="Detected java.util.Random without SecureRandom; predictable PRNG in security operations.",
                confidence=Confidence.MEDIUM
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
                details="Violation of Clause 4.1.5.18 & 4.1.5.19: Predictable PRNG detected."
            )
        else:
            findings.append(Finding(
                description="No explicit random number generator detected; manual inspection recommended.",
                confidence=Confidence.LOW
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
                details="PRNG mechanism undetermined."
            )
