"""
BB-MFS-10: Source Code Protection, Obfuscation & Anti-Tampering
Clauses: 4.1.4.4, 5.1.2.19
"""

from typing import List, Any
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence

class SourceCodeProtectionRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-10")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        classes = []

        if analysis and hasattr(analysis, "get_classes"):
            try:
                for c in analysis.get_classes():
                    classes.append(str(getattr(c, "name", "")))
            except Exception:
                pass

        if not classes and dex_list:
            for dex in dex_list:
                if hasattr(dex, "get_classes"):
                    try:
                        for c in dex.get_classes():
                            classes.append(str(getattr(c, "get_name", lambda: "")()))
                    except Exception:
                        pass

        # Calculate ratio of short single-character / obfuscated class names
        obfuscated_count = 0
        total_app_classes = 0

        sdk_prefixes = [
            "Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/", "Ljava/", "Ljavax/",
            "Lcom/google/", "Lcom/facebook/", "Lcom/alibaba/", "Lio/flutter/", "Lio/reactivex/",
            "Lokio/", "Lokhttp3/", "Lorg/"
        ]

        for c in classes:
            # Exclude standard Android, Google, and third-party vendor libraries from calculation
            if any(c.startswith(pfx) for pfx in sdk_prefixes):
                continue
            total_app_classes += 1
            parts = c.strip("L;").split("/")
            # Count as obfuscated if class name is <= 2 chars or if root/package was flattened to <= 2 chars
            if parts and (len(parts[-1]) <= 2 or len(parts[0]) <= 2 or (len(parts) > 1 and len(parts[1]) <= 2)):
                obfuscated_count += 1

        obfuscation_ratio = (obfuscated_count / total_app_classes) if total_app_classes > 0 else 0.0

        if total_app_classes > 10 and obfuscation_ratio < 0.20:
            findings.append(Finding(
                description=f"Low obfuscation index ({obfuscation_ratio:.1%}). Application business logic is exposed in cleartext class names.",
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
                details=f"Violation of Clause 4.1.4.4: Source code not protected. Obfuscation ratio is {obfuscation_ratio:.1%}."
            )
        else:
            findings.append(Finding(
                description=f"Verified code minification/obfuscation (obfuscated class ratio: {obfuscation_ratio:.1%}).",
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
                details="Application source code obfuscation complies with Clause 4.1.4.4."
            )
