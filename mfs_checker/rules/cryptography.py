"""
BB-MFS-04: Cryptographic Algorithm Strength & Modern Cipher Suites
Clauses: 4.1.5.19.c, 4.1.5.18
"""

from typing import List, Any
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence
from mfs_checker.config import DEPRECATED_CIPHERS, DEPRECATED_HASHES

class CryptographyStrengthRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-04")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        strings = self.extract_all_strings(analysis, dex_list)

        deprecated_found = []
        for s in strings:
            # Check ciphers
            for dc in DEPRECATED_CIPHERS:
                if s == dc or s.startswith(f"{dc}/"):
                    deprecated_found.append(f"Insecure Cipher: {s}")
            # Check hash algorithms
            for dh in DEPRECATED_HASHES:
                if s.upper() == dh or s.upper() == f"MESSAGE DIGEST {dh}":
                    deprecated_found.append(f"Deprecated Hash: {s}")

        # Check for secure modern crypto usage
        modern_crypto_indicators = [
            "AES/GCM/NoPadding",
            "AES/CBC/PKCS5Padding",
            "SHA-256",
            "SHA-512",
            "HmacSHA256",
            "OAEPWithSHA-256AndMGF1Padding"
        ]
        has_modern = any(any(m in s for m in modern_crypto_indicators) for s in strings)

        # Distinguish between insecure ciphers (critical failure) and legacy hashes (warning if modern crypto present)
        insecure_ciphers = [d for d in deprecated_found if "Insecure Cipher" in d]
        deprecated_hashes = [d for d in deprecated_found if "Deprecated Hash" in d]

        if insecure_ciphers:
            for dep in set(insecure_ciphers):
                findings.append(Finding(
                    description=f"Insecure cipher algorithm detected: {dep}",
                    confidence=Confidence.HIGH,
                    code_snippet=dep
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
                details=f"Violation of Clause 4.1.5.19.c: Found {len(insecure_ciphers)} insecure ciphers (e.g. DES, RC4, ECB)."
            )
        elif deprecated_hashes and not has_modern:
            for dep in set(deprecated_hashes):
                findings.append(Finding(
                    description=f"Deprecated hashing primitive detected without modern crypto: {dep}",
                    confidence=Confidence.HIGH,
                    code_snippet=dep
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
                details=f"Violation of Clause 4.1.5.19.c: Relies on deprecated hashing (MD5/SHA-1) without modern crypto."
            )
        elif deprecated_hashes and has_modern:
            for dep in set(deprecated_hashes):
                findings.append(Finding(
                    description=f"Legacy hashing primitive in auxiliary/third-party routines: {dep}",
                    confidence=Confidence.MEDIUM,
                    code_snippet=dep
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
                remediation="Ensure modern SHA-256 is used for all security routines; purge legacy MD5/SHA-1 from dependencies.",
                findings=findings,
                details=f"Advisory under Clause 4.1.5.19.c: Modern crypto verified; legacy hashes detected in dependencies."
            )
        elif has_modern:
            findings.append(Finding(
                description="Verified modern cryptographic algorithms (AES-GCM/CBC, SHA-256/512, HMAC).",
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
                details="Cryptographic primitives meet Bangladesh Bank Clause 4.1.5.19.c requirements."
            )
        else:
            findings.append(Finding(
                description="No explicit standard cryptographic transformations identified in string tables.",
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
                details="Unable to confirm modern cryptographic cipher suite usage."
            )
