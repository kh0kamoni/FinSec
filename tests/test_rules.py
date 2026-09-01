"""
Unit Tests for all 11 Bangladesh Bank Cybersecurity Framework Compliance Rules.
"""

import pytest
from mfs_checker.models import RuleStatus, ComplianceTier
from mfs_checker.rules.storage import DataAtRestRule
from mfs_checker.rules.logging import SensitiveLoggingRule
from mfs_checker.rules.transport import TransportSecurityRule
from mfs_checker.rules.cryptography import CryptographyStrengthRule
from mfs_checker.rules.keystore import KeystoreSecurityRule
from mfs_checker.rules.signing import TransactionSigningRule
from mfs_checker.rules.randomness import CryptographicRandomnessRule
from mfs_checker.rules.permissions import LeastPrivilegePermissionsRule
from mfs_checker.rules.manifest import ManifestHardeningRule
from mfs_checker.rules.obfuscation import SourceCodeProtectionRule
from mfs_checker.rules.secrets import HardcodedSecretsRule
from mfs_checker.engine import ComplianceEngine

from tests.mock_apk_builder import build_compliant_mock, build_vulnerable_mock

def test_data_at_rest_rule():
    rule = DataAtRestRule()
    apk_c, dex_c, analysis_c = build_compliant_mock()
    res_c = rule.evaluate(apk_c, dex_c, analysis_c)
    assert res_c.status == RuleStatus.PASSED

    apk_v, dex_v, analysis_v = build_vulnerable_mock()
    res_v = rule.evaluate(apk_v, dex_v, analysis_v)
    assert res_v.status == RuleStatus.FAILED

def test_sensitive_logging_rule():
    rule = SensitiveLoggingRule()
    apk_v, dex_v, analysis_v = build_vulnerable_mock()
    res_v = rule.evaluate(apk_v, dex_v, analysis_v)
    assert res_v.status == RuleStatus.FAILED

    apk_c, dex_c, analysis_c = build_compliant_mock()
    res_c = rule.evaluate(apk_c, dex_c, analysis_c)
    assert res_c.status == RuleStatus.PASSED

def test_transport_security_rule():
    rule = TransportSecurityRule()
    apk_c, dex_c, analysis_c = build_compliant_mock()
    res_c = rule.evaluate(apk_c, dex_c, analysis_c)
    assert res_c.status == RuleStatus.PASSED

    apk_v, dex_v, analysis_v = build_vulnerable_mock()
    res_v = rule.evaluate(apk_v, dex_v, analysis_v)
    assert res_v.status == RuleStatus.FAILED

def test_cryptography_strength_rule():
    rule = CryptographyStrengthRule()
    apk_c, dex_c, analysis_c = build_compliant_mock()
    res_c = rule.evaluate(apk_c, dex_c, analysis_c)
    assert res_c.status == RuleStatus.PASSED

    apk_v, dex_v, analysis_v = build_vulnerable_mock()
    res_v = rule.evaluate(apk_v, dex_v, analysis_v)
    assert res_v.status == RuleStatus.FAILED

def test_keystore_security_rule():
    rule = KeystoreSecurityRule()
    apk_c, dex_c, analysis_c = build_compliant_mock()
    res_c = rule.evaluate(apk_c, dex_c, analysis_c)
    assert res_c.status == RuleStatus.PASSED

def test_transaction_signing_rule():
    rule = TransactionSigningRule()
    apk_c, dex_c, analysis_c = build_compliant_mock()
    res_c = rule.evaluate(apk_c, dex_c, analysis_c)
    assert res_c.status == RuleStatus.PASSED

    apk_v, dex_v, analysis_v = build_vulnerable_mock()
    res_v = rule.evaluate(apk_v, dex_v, analysis_v)
    assert res_v.status == RuleStatus.FAILED

def test_cryptographic_randomness_rule():
    rule = CryptographicRandomnessRule()
    apk_c, dex_c, analysis_c = build_compliant_mock()
    res_c = rule.evaluate(apk_c, dex_c, analysis_c)
    assert res_c.status == RuleStatus.PASSED

    apk_v, dex_v, analysis_v = build_vulnerable_mock()
    res_v = rule.evaluate(apk_v, dex_v, analysis_v)
    assert res_v.status == RuleStatus.FAILED

def test_least_privilege_permissions_rule():
    rule = LeastPrivilegePermissionsRule()
    apk_c, dex_c, analysis_c = build_compliant_mock()
    res_c = rule.evaluate(apk_c, dex_c, analysis_c)
    assert res_c.status == RuleStatus.PASSED

    apk_v, dex_v, analysis_v = build_vulnerable_mock()
    res_v = rule.evaluate(apk_v, dex_v, analysis_v)
    assert res_v.status == RuleStatus.FAILED

def test_manifest_hardening_rule():
    rule = ManifestHardeningRule()
    apk_c, dex_c, analysis_c = build_compliant_mock()
    res_c = rule.evaluate(apk_c, dex_c, analysis_c)
    assert res_c.status == RuleStatus.PASSED

    apk_v, dex_v, analysis_v = build_vulnerable_mock()
    res_v = rule.evaluate(apk_v, dex_v, analysis_v)
    assert res_v.status == RuleStatus.FAILED

def test_hardcoded_secrets_rule():
    rule = HardcodedSecretsRule()
    apk_v, dex_v, analysis_v = build_vulnerable_mock()
    res_v = rule.evaluate(apk_v, dex_v, analysis_v)
    assert res_v.status == RuleStatus.FAILED

    apk_c, dex_c, analysis_c = build_compliant_mock()
    res_c = rule.evaluate(apk_c, dex_c, analysis_c)
    assert res_c.status == RuleStatus.PASSED

def test_full_engine_mock_audits():
    engine = ComplianceEngine()

    apk_c, dex_c, analysis_c = build_compliant_mock()
    sc_c = engine.audit_mock(apk_c, dex_c, analysis_c, app_name="CompliantFintech")
    assert sc_c.maturity_score >= 85.0
    assert sc_c.tier == ComplianceTier.TIER_1_COMPLIANT
    assert sc_c.critical_violations == 0

    apk_v, dex_v, analysis_v = build_vulnerable_mock()
    sc_v = engine.audit_mock(apk_v, dex_v, analysis_v, app_name="VulnerableFintech")
    assert sc_v.tier == ComplianceTier.TIER_3_HIGH_RISK
    assert sc_v.critical_violations >= 1
