"""
BB-MFS-01: Data at Rest Encryption & End-to-End Encryption (E2EE)
Clauses: 4.1.5.2, 4.1.5.17, 4.1.5.23
"""

from typing import List, Any
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence

class DataAtRestRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-01")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        has_encrypted_storage = False
        has_unencrypted_storage = False

        strings = self.extract_all_strings(analysis, dex_list)

        # Secure Storage Primitives
        secure_indicators = [
            "androidx/security/crypto/EncryptedSharedPreferences",
            "androidx.security.crypto.EncryptedSharedPreferences",
            "EncryptedSharedPreferences",
            "androidx/security/crypto/MasterKey",
            "androidx.security.crypto.MasterKey",
            "androidx/security/crypto/MasterKeys",
            "MasterKey",
            "MasterKeys",
            "net/sqlcipher/database/SQLiteDatabase",
            "net.sqlcipher.database.SQLiteDatabase",
            "sqlcipher",
            "SQLCipher",
            "io/realm/RealmConfiguration$Builder;->encryptionKey",
            "com/google/crypto/tink/Aead",
            "com/google/crypto/tink",
            "flutter_secure_storage"
        ]

        # Insecure / Plaintext Storage Sinks
        insecure_storage_sinks = [
            "android/content/Context;->getSharedPreferences",
            "android/database/sqlite/SQLiteOpenHelper",
            "android/database/sqlite/SQLiteDatabase;->openOrCreateDatabase"
        ]

        # Scan DEX analysis classes & method calls
        if analysis and hasattr(analysis, "get_classes"):
            for cls in analysis.get_classes():
                c_name = getattr(cls, "name", "")
                for ind in secure_indicators:
                    if ind in c_name:
                        has_encrypted_storage = True
                        break

        # Check strings as well
        for s in strings:
            if any(ind in s for ind in secure_indicators):
                has_encrypted_storage = True
                break

        # Check for unencrypted database or preference references
        for s in strings:
            if any(sink in s for sink in insecure_storage_sinks):
                has_unencrypted_storage = True
                break

        if has_encrypted_storage:
            findings.append(Finding(
                description="Verified presence of EncryptedSharedPreferences or SQLCipher for data protection at rest.",
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
                details="Cryptographic at-rest storage mechanisms verified (EncryptedSharedPreferences / SQLCipher)."
            )
        elif has_unencrypted_storage:
            findings.append(Finding(
                description="Detected standard unencrypted SharedPreferences or SQLiteDatabase without SQLCipher or EncryptedSharedPreferences.",
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
                details="Violation of Clauses 4.1.5.2 and 4.1.5.17: Application uses unencrypted local storage."
            )
        else:
            # Minimal/unknown storage usage
            findings.append(Finding(
                description="No explicit encrypted storage primitives detected; manual code review advised.",
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
                penalty=5,
                remediation=self.remediation,
                findings=findings,
                details="No encrypted storage framework confirmed in DEX bytecode."
            )
