"""
BB-MFS-11: Embedded Credentials, Hardcoded API Secrets & Private Keys
Clauses: Appendix C (Items 7, 8, 34)
"""

from typing import List, Any
import re
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence
from mfs_checker.config import HIGH_ENTROPY_THRESHOLD, MIN_SECRET_LENGTH

class HardcodedSecretsRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-11")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        strings = self.extract_all_strings(analysis, dex_list)

        secret_regexes = {
            "Private RSA/EC Key": re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
            "AWS Access Key ID": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
            "Google API Key": re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b'),
            "JSON Web Token (JWT)": re.compile(r'\beyJ[A-Za-z0-9-_=]{15,}\.[A-Za-z0-9-_=]{15,}\.[A-Za-z0-9-_.+/=]{10,}\b'),
            "Generic Payment Secret Heuristic": re.compile(r'(?:api_key|client_secret|app_secret|merchant_secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.IGNORECASE)
        }

        detected_secrets = []
        for s in strings:
            for sec_type, regex in secret_regexes.items():
                match = regex.search(s)
                if match:
                    val = match.group(0)
                    # Mask value
                    masked = val[:4] + "*" * (len(val) - 8) + val[-4:] if len(val) > 8 else "***"
                    detected_secrets.append((sec_type, masked))
                    if len(detected_secrets) >= 8:
                        break
            if len(detected_secrets) >= 8:
                break

        # High entropy string check for suspected secret constants
        high_entropy_candidates = []
        for s in strings:
            if MIN_SECRET_LENGTH <= len(s) <= 80 and " " not in s and "/" not in s and "." not in s:
                ent = self.calculate_entropy(s)
                if ent >= HIGH_ENTROPY_THRESHOLD and re.search(r'[0-9]', s) and re.search(r'[a-zA-Z]', s):
                    # Check for obvious false positives (e.g. hash names, identifiers)
                    if not s.isupper() and not s.islower():
                        high_entropy_candidates.append((s, ent))
                        if len(high_entropy_candidates) >= 5:
                            break

        if detected_secrets:
            for stype, masked in detected_secrets[:5]:
                findings.append(Finding(
                    description=f"High-risk embedded credential detected: {stype} ({masked})",
                    confidence=Confidence.HIGH,
                    code_snippet=masked
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
                details=f"Violation of Appendix C: Found {len(detected_secrets)} embedded production credentials."
            )
        elif high_entropy_candidates:
            for cand, ent in high_entropy_candidates[:3]:
                masked = cand[:3] + "..." + cand[-3:]
                findings.append(Finding(
                    description=f"Suspicious high-entropy string constant ({ent:.2f} bits/char): {masked}",
                    confidence=Confidence.MEDIUM,
                    code_snippet=masked
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
                details="Potential embedded tokens identified via Shannon entropy heuristics."
            )
        else:
            findings.append(Finding(
                description="Verified: No hardcoded secrets, private keys, or abnormal high-entropy tokens detected.",
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
                details="No hardcoded secrets detected in DEX string pool."
            )
