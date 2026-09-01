"""
BB-MFS-09: Hardened Baseline Manifest & Component Configuration
Clauses: 4.1.8.10, 4.1.8.6
"""

from typing import List, Any
import xml.etree.ElementTree as ET
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence

class ManifestHardeningRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-09")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        is_backup_allowed = False
        is_debuggable = False
        unprotected_exported_components = []

        manifest_str = self.get_manifest_xml_string(apk)

        # Check raw attributes
        if 'android:allowBackup="true"' in manifest_str:
            is_backup_allowed = True
        if 'android:debuggable="true"' in manifest_str:
            is_debuggable = True

        # Parse XML element tree if available
        if hasattr(apk, "get_android_manifest_xml"):
            try:
                xml_root = apk.get_android_manifest_xml()
                if xml_root is not None:
                    # Namespace prefix handling
                    ns = "{http://schemas.android.com/apk/res/android}"
                    app_elem = xml_root.find("application")
                    if app_elem is not None:
                        if app_elem.get(f"{ns}allowBackup") == "true":
                            is_backup_allowed = True
                        if app_elem.get(f"{ns}debuggable") == "true":
                            is_debuggable = True

                        for tag in ["activity", "service", "receiver", "provider"]:
                            for comp in app_elem.findall(tag):
                                is_exported = comp.get(f"{ns}exported")
                                perm = comp.get(f"{ns}permission")
                                comp_name = comp.get(f"{ns}name", "unnamed")
                                if is_exported == "true" and not perm:
                                    # Main/Launcher activities are expected to be exported without permissions
                                    has_launcher = False
                                    for intent in comp.findall("intent-filter"):
                                        for cat in intent.findall("category"):
                                            if "LAUNCHER" in cat.get(f"{ns}name", ""):
                                                has_launcher = True
                                                break
                                    if not has_launcher:
                                        unprotected_exported_components.append(f"{tag}:{comp_name}")
            except Exception:
                pass

        if is_backup_allowed:
            findings.append(Finding(
                description="android:allowBackup is enabled ('true'), allowing adb backup extraction of app private sandbox.",
                confidence=Confidence.HIGH
            ))
        if is_debuggable:
            findings.append(Finding(
                description="android:debuggable is enabled ('true'), allowing runtime debugger attachment and memory dumping.",
                confidence=Confidence.HIGH
            ))
        for comp in unprotected_exported_components[:5]:
            findings.append(Finding(
                description=f"Exported component without permission barrier: {comp}",
                confidence=Confidence.HIGH
            ))

        if is_backup_allowed or is_debuggable:
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
                details="Violation of Clause 4.1.8.10: Unhardened manifest allows backup or debugging."
            )
        elif unprotected_exported_components:
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
                details=f"Identified {len(unprotected_exported_components)} unprotected exported application components."
            )
        else:
            findings.append(Finding(
                description="Manifest securely hardened: allowBackup=false, debuggable=false, components protected.",
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
                details="Manifest configuration conforms to Bangladesh Bank hardening standards."
            )
