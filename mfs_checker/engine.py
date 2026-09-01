"""
Static Audit Engine Orchestrator for Bangladesh Bank Compliance Checking.
"""

import os
import hashlib
import time
from typing import Optional, List, Dict, Any

from mfs_checker.models import ComplianceScorecard, RuleResult, RuleStatus, Severity, ComplianceTier
from mfs_checker.rules import get_all_rules
from mfs_checker.config import FRAMEWORK_NAME, REGULATOR, ISSUE_DATE

class ComplianceEngine:
    """Main audit executor for evaluating APKs against Bangladesh Bank Cybersecurity Framework."""

    def __init__(self, rules: Optional[List[Any]] = None):
        self.rules = rules if rules is not None else get_all_rules()

    @staticmethod
    def compute_sha256(file_path: str) -> str:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def audit_apk(self, apk_path: str) -> ComplianceScorecard:
        """
        Execute full compliance audit on an Android APK file.
        :param apk_path: Absolute or relative path to the APK
        :return: ComplianceScorecard containing all findings and maturity score
        """
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")

        start_time = time.time()
        file_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
        sha256_hash = self.compute_sha256(apk_path)

        # Silence verbose third-party loggers for speed
        try:
            from loguru import logger
            import sys
            logger.remove()
            logger.add(sys.stderr, level="ERROR")
        except Exception:
            pass

        # Handle split APKs bundle (.apks) if provided
        import zipfile
        import tempfile
        from androguard.misc import AnalyzeAPK

        actual_apk_path = apk_path
        temp_dir = None
        if apk_path.lower().endswith(".apks") or zipfile.is_zipfile(apk_path):
            try:
                with zipfile.ZipFile(apk_path) as z:
                    names = z.namelist()
                    base_candidates = [n for n in names if n == "base.apk" or n.endswith("/base.apk")]
                    if not base_candidates:
                        base_candidates = [n for n in names if n.endswith(".apk")]
                    if base_candidates:
                        temp_dir = tempfile.TemporaryDirectory()
                        actual_apk_path = z.extract(base_candidates[0], temp_dir.name)
            except Exception:
                pass

        try:
            apk_obj, dex_list, analysis_obj = AnalyzeAPK(actual_apk_path)
        finally:
            if temp_dir:
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass

        # Extract app metadata
        package_name = apk_obj.get_package() or "unknown.package"
        version_name = apk_obj.get_androidversion_name() or "1.0"
        version_code = str(apk_obj.get_androidversion_code() or "1")
        app_name = apk_obj.get_app_name() or package_name

        # Run all compliance rules
        rule_results: List[RuleResult] = []
        total_penalties = 0
        passed_count = 0
        failed_count = 0
        warning_count = 0
        critical_violations = 0

        for rule in self.rules:
            try:
                res = rule.evaluate(apk_obj, dex_list, analysis_obj)
            except Exception as e:
                # Resilient fallback if obfuscation causes unexpected AST parsing errors
                res = RuleResult(
                    rule_id=rule.rule_id,
                    clause=rule.clause,
                    title=rule.title,
                    function=rule.function,
                    category=rule.category,
                    status=RuleStatus.WARNING,
                    severity=rule.severity,
                    penalty=2,
                    remediation=rule.remediation,
                    details=f"Evaluation warning due to bytecode analysis error: {str(e)}"
                )

            rule_results.append(res)
            total_penalties += res.penalty

            if res.status == RuleStatus.PASSED:
                passed_count += 1
            elif res.status == RuleStatus.FAILED:
                failed_count += 1
                if res.severity == Severity.CRITICAL:
                    critical_violations += 1
            elif res.status == RuleStatus.WARNING:
                warning_count += 1

        maturity_score = max(0.0, 100.0 - float(total_penalties))

        # Assign Compliance Tier per Bangladesh Bank standards
        if critical_violations > 0 or maturity_score < 70.0:
            tier = ComplianceTier.TIER_3_HIGH_RISK
        elif maturity_score >= 85.0:
            tier = ComplianceTier.TIER_1_COMPLIANT
        else:
            tier = ComplianceTier.TIER_2_CONDITIONAL

        duration = time.time() - start_time

        return ComplianceScorecard(
            app_name=app_name,
            package_name=package_name,
            version_name=version_name,
            version_code=version_code,
            sha256_hash=sha256_hash,
            apk_size_mb=file_size_mb,
            maturity_score=maturity_score,
            tier=tier,
            total_rules=len(rule_results),
            passed_rules=passed_count,
            failed_rules=failed_count,
            warning_rules=warning_count,
            critical_violations=critical_violations,
            rule_results=rule_results,
            execution_time_seconds=duration
        )

    def audit_mock(self, mock_apk: Any, mock_dex_list: List[Any], mock_analysis: Any, app_name: str = "MockFintechApp") -> ComplianceScorecard:
        """Audit mock objects directly (used in unit testing and headless environments)."""
        start_time = time.time()
        rule_results: List[RuleResult] = []
        total_penalties = 0
        passed_count = 0
        failed_count = 0
        warning_count = 0
        critical_violations = 0

        for rule in self.rules:
            res = rule.evaluate(mock_apk, mock_dex_list, mock_analysis)
            rule_results.append(res)
            total_penalties += res.penalty

            if res.status == RuleStatus.PASSED:
                passed_count += 1
            elif res.status == RuleStatus.FAILED:
                failed_count += 1
                if res.severity == Severity.CRITICAL:
                    critical_violations += 1
            elif res.status == RuleStatus.WARNING:
                warning_count += 1

        maturity_score = max(0.0, 100.0 - float(total_penalties))

        if critical_violations > 0 or maturity_score < 70.0:
            tier = ComplianceTier.TIER_3_HIGH_RISK
        elif maturity_score >= 85.0:
            tier = ComplianceTier.TIER_1_COMPLIANT
        else:
            tier = ComplianceTier.TIER_2_CONDITIONAL

        return ComplianceScorecard(
            app_name=app_name,
            package_name="com.fintech.mock",
            version_name="1.0.0",
            version_code="100",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            apk_size_mb=12.5,
            maturity_score=maturity_score,
            tier=tier,
            total_rules=len(rule_results),
            passed_rules=passed_count,
            failed_rules=failed_count,
            warning_rules=warning_count,
            critical_violations=critical_violations,
            rule_results=rule_results,
            execution_time_seconds=time.time() - start_time
        )
