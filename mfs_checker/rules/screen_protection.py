"""
BB-MFS-13: Screen Capture, Screenshot & Tapjacking Overlay Protection
Clauses: 4.1.8.6
"""

from typing import List, Any
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence

class ScreenProtectionRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-13")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        strings = self.extract_all_strings(analysis, dex_list)

        # Look for FLAG_SECURE usage (0x2000 / 8192) or explicit WindowManager FLAG_SECURE references
        has_flag_secure = False
        for s in strings:
            if "FLAG_SECURE" in s or "flag_secure" in s.lower():
                has_flag_secure = True
                break

        # Check manifest XML for filterTouchesWhenObscured
        has_touch_filtering = False
        try:
            if hasattr(apk, "get_android_manifest_xml"):
                manifest_xml = apk.get_android_manifest_xml()
                if manifest_xml is not None:
                    import xml.etree.ElementTree as ET
                    xml_str = ET.tostring(manifest_xml, encoding='utf-8').decode('utf-8', errors='ignore')
                    if "filterTouchesWhenObscured" in xml_str:
                        has_touch_filtering = True
        except Exception:
            pass

        if has_flag_secure or has_touch_filtering:
            if has_flag_secure:
                findings.append(Finding(
                    description="Verified: FLAG_SECURE screen capture protection identified.",
                    confidence=Confidence.HIGH
                ))
            if has_touch_filtering:
                findings.append(Finding(
                    description="Verified: filterTouchesWhenObscured overlay defense declared in manifest/views.",
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
                details="Complies with Clause 4.1.8.6: Implements anti-screen capture / overlay shielding."
            )
        else:
            findings.append(Finding(
                description="No FLAG_SECURE or filterTouchesWhenObscured configurations identified in bytecode/manifest.",
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
                details="Violation of Clause 4.1.8.6: Missing protection against screen capture and tapjacking overlays."
            )
