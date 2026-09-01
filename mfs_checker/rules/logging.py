"""
BB-MFS-02: Prohibition of Logging Sensitive Authentication Data (SAD) & CHD
Clauses: 4.1.3.21.b, 6.1.3.17.b, 4.1.1.6
"""

from typing import List, Any
import re
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence
from mfs_checker.config import SENSITIVE_PARAM_KEYWORDS

class SensitiveLoggingRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-02")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        strings = self.extract_all_strings(analysis, dex_list)

        # Insecure logging signatures
        log_sinks = [
            "Landroid/util/Log;->d(",
            "Landroid/util/Log;->v(",
            "Landroid/util/Log;->i(",
            "Landroid/util/Log;->w(",
            "Landroid/util/Log;->e(",
            "Ljava/lang/System;->out",
            "printStackTrace"
        ]

        # Scan for authentic credential format strings in logging sinks (excluding UI tags, SQL, URLs)
        leak_re = re.compile(
            r'(?:(?:user[_\s]?pin|login[_\s]?pin|pin[_\s]?code|user[_\s]?otp|sms[_\s]?otp|otp[_\s]?code|cvv2?|card[_\s]?number|account[_\s]?password)[=:\s]+[%$\'\"0-9]|\b(?:pin|otp|password)\s+is\s+[%$\'\"0-9])',
            re.IGNORECASE
        )
        exclusions = [
            'the tag for', 'delete from', 'select ', 'update ', 'insert into',
            'view_', 'input_hint_', 'fragment_', 'dialog_', 'https://', 'http://',
            '@string/', '@layout/', '@id/', 'invalid. received', 'swipe_btn', 'where '
        ]

        leaked_log_strings = []
        for s in strings:
            if len(s) < 150 and leak_re.search(s):
                if not any(ex in s.lower() for ex in exclusions):
                    leaked_log_strings.append(s)
                    if len(leaked_log_strings) >= 10:
                        break

        has_log_sinks = any(sink in "".join(strings) for sink in ["Landroid/util/Log;", "System.out", "Log.d", "Log.i", "Log.e", "Log.v", "Log.w"])

        # Also inspect analysis method calls if available
        if analysis and hasattr(analysis, "get_methods"):
            for m in analysis.get_methods():
                m_str = str(m)
                if any(sink in m_str for sink in ["Log;->d", "Log;->v", "Log;->i"]):
                    has_log_sinks = True
                    break

        if leaked_log_strings:
            for leak in leaked_log_strings[:5]:
                findings.append(Finding(
                    description=f"Potential sensitive authentication data leak in logging format: '{leak}'",
                    confidence=Confidence.HIGH,
                    code_snippet=leak
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
                details=f"Violation of Clause 4.1.3.21.b & 6.1.3.17.b: Found {len(leaked_log_strings)} log formats referencing SAD/CHD keywords."
            )
        elif has_log_sinks:
            findings.append(Finding(
                description="General android.util.Log calls detected; ensure R8/ProGuard strips them in production.",
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
                details="Logging calls present in APK; no obvious plaintext credential log formats found."
            )
        else:
            findings.append(Finding(
                description="Verified: android.util.Log stripped or absent from release bytecode.",
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
                details="No sensitive logging calls detected."
            )
