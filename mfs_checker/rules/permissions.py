"""
BB-MFS-08: Principle of Least Privilege & Permission Baseline Adherence
Clauses: 4.1.2.5, 4.1.8.4
"""

from typing import List, Any, Set
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence
from mfs_checker.config import DANGEROUS_MFS_PERMISSIONS, BENIGN_MFS_PERMISSIONS

class LeastPrivilegePermissionsRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-08")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        requested_permissions: Set[str] = set()

        if hasattr(apk, "get_permissions"):
            try:
                for p in apk.get_permissions():
                    requested_permissions.add(str(p))
            except Exception:
                pass
        elif hasattr(apk, "permissions"):
            requested_permissions = set(getattr(apk, "permissions", []))

        from mfs_checker.config import INVASIVE_MALWARE_PERMISSIONS, FUNCTIONAL_FINTECH_PERMISSIONS

        flagged_invasive = [p for p in requested_permissions if p in INVASIVE_MALWARE_PERMISSIONS]
        flagged_functional = [p for p in requested_permissions if p in FUNCTIONAL_FINTECH_PERMISSIONS]

        if flagged_invasive:
            for dp in flagged_invasive:
                findings.append(Finding(
                    description=f"Severe/Invasive permission violating least privilege: {dp}",
                    confidence=Confidence.HIGH,
                    metadata={"permission": dp}
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
                details=f"Violation of Clause 4.1.2.5 & 4.1.8.4: {len(flagged_invasive)} invasive malware/spyware permissions requested ({', '.join([p.split('.')[-1] for p in flagged_invasive])})."
            )
        elif flagged_functional:
            for fp in flagged_functional:
                findings.append(Finding(
                    description=f"Functionally justified permission requiring operational governance: {fp}",
                    confidence=Confidence.MEDIUM,
                    metadata={"permission": fp}
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
                remediation="Ensure functional permissions (e.g. location for agent locator, contacts for recharge) declare explicit in-app runtime consent.",
                findings=findings,
                details=f"Advisory under Clause 4.1.2.5: {len(flagged_functional)} functional permissions requested ({', '.join([p.split('.')[-1] for p in flagged_functional])})."
            )
        else:
            findings.append(Finding(
                description=f"Permissions strictly comply with minimal Bangladesh Bank MFS baseline ({len(requested_permissions)} total permissions).",
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
                details="Permission profile strictly conforms to least privilege baseline."
            )
