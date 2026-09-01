"""
Mock Objects and Lightweight APK Fixture Generator for Unit Testing.
"""

from typing import List, Set, Optional

class MockAPK:
    """Mock APK object providing manifest attributes and permissions."""

    def __init__(
        self,
        package: str = "com.bdfintech.testapp",
        permissions: Optional[List[str]] = None,
        allow_backup: bool = False,
        debuggable: bool = False,
        uses_cleartext: bool = False,
        app_name: str = "TestFintech"
    ):
        self.package = package
        self.permissions = permissions or [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.USE_BIOMETRIC"
        ]
        self.allow_backup = allow_backup
        self.debuggable = debuggable
        self.uses_cleartext = uses_cleartext
        self.app_name = app_name

        # Construct XML representation
        backup_str = 'android:allowBackup="true"' if allow_backup else 'android:allowBackup="false"'
        debug_str = 'android:debuggable="true"' if debuggable else 'android:debuggable="false"'
        cleartext_str = 'android:usesCleartextTraffic="true"' if uses_cleartext else 'android:usesCleartextTraffic="false"'

        self.xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}">
    {''.join(f'<uses-permission android:name="{p}" />' for p in self.permissions)}
    <application {backup_str} {debug_str} {cleartext_str} android:label="{app_name}">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""

    def get_package(self) -> str:
        return self.package

    def get_permissions(self) -> List[str]:
        return self.permissions

    def get_app_name(self) -> str:
        return self.app_name

    def get_androidversion_name(self) -> str:
        return "1.0.0"

    def get_androidversion_code(self) -> str:
        return "1"


class MockAnalysis:
    """Mock Analysis object providing classes and strings."""

    def __init__(self, strings: Optional[List[str]] = None, classes: Optional[List[str]] = None):
        self._strings = strings or []
        self._classes = [MockClass(c) for c in (classes or [])]

    def get_strings(self) -> List[str]:
        return self._strings

    def get_classes(self) -> List["MockClass"]:
        return self._classes


class MockClass:
    def __init__(self, name: str):
        self.name = name


def build_compliant_mock() -> tuple:
    """Returns (apk, dex_list, analysis) for a fully compliant fintech app."""
    apk = MockAPK(
        package="com.bkash.compliant",
        permissions=[
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.CAMERA",
            "android.permission.USE_BIOMETRIC"
        ],
        allow_backup=False,
        debuggable=False,
        uses_cleartext=False
    )
    strings = [
        "androidx/security/crypto/EncryptedSharedPreferences",
        "androidx/security/crypto/MasterKey",
        "okhttp3/CertificatePinner",
        "AES/GCM/NoPadding",
        "SHA-256",
        "AndroidKeyStore",
        "java/security/Signature",
        "SHA256withRSA",
        "java/security/SecureRandom",
        "rootbeer",
        "/system/bin/su",
        "FLAG_SECURE",
        "androidx/biometric/BiometricPrompt",
        "CryptoObject"
    ]
    # Add obfuscated class names
    classes = [f"Lcom/bkash/a/{chr(97 + i)};" for i in range(15)]
    analysis = MockAnalysis(strings=strings, classes=classes)
    return apk, [], analysis


def build_vulnerable_mock() -> tuple:
    """Returns (apk, dex_list, analysis) for a non-compliant app with critical flaws."""
    apk = MockAPK(
        package="com.insecure.roguefintech",
        permissions=[
            "android.permission.INTERNET",
            "android.permission.SEND_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.SYSTEM_ALERT_WINDOW"
        ],
        allow_backup=True,
        debuggable=True,
        uses_cleartext=True
    )
    strings = [
        "android/content/Context;->getSharedPreferences",
        "android/database/sqlite/SQLiteOpenHelper",
        "Log.d(TAG, user_pin = " + "1234",
        "http://insecure-api.fintech.bd/v1/transfer",
        "DES",
        "AES/ECB/PKCS5Padding",
        "MD5",
        "java.util.Random",
        "AKIAIOSFODNN7EXAMPLE",  # Leaked AWS Key
        "AIzaSyD-1234567890abcdefghijklmnopqrstuv"  # Leaked Google API Key
    ]
    classes = [
        "Lcom/insecure/roguefintech/AccountDetailsActivity;",
        "Lcom/insecure/roguefintech/TransferMoneyService;",
        "Lcom/insecure/roguefintech/TransactionDatabaseHelper;"
    ]
    analysis = MockAnalysis(strings=strings, classes=classes)
    return apk, [], analysis
