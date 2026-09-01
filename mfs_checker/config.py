"""
Configuration and Regulatory Baselines for Bangladesh Bank Cybersecurity Framework v1.0 (Feb 2025).
"""

from typing import Dict, List, Set

# Regulatory Framework Metadata
FRAMEWORK_NAME = "Cybersecurity Framework Version 1.0"
REGULATOR = "Bangladesh Bank"
ISSUE_DATE = "February 2025"
REGULATED_ENTITIES = [
    "Banks (PLC / Foreign)",
    "Non-Bank Financial Institutions (NBFIs)",
    "Mobile Financial Service Providers (MFSP)",
    "Payment Service Providers (PSP)",
    "Payment System Operators (PSO)"
]

# Penalty Weights for BB Maturity Score Calculation (0-100 scale)
SEVERITY_WEIGHTS = {
    "CRITICAL": 15,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0
}

# 11 Core Regulatory Clauses Mapped to Static Mobile Verification
BB_CLAUSE_DEFINITIONS: Dict[str, Dict] = {
    "BB-MFS-01": {
        "clause": "4.1.5.2, 4.1.5.17, 4.1.5.23",
        "title": "Encryption of Data at Rest & End-to-End Encryption (E2EE)",
        "function": "PROTECT",
        "category": "Data Security",
        "severity": "CRITICAL",
        "description": "Sensitive consumer data (account, transaction, credentials) stored in local databases or preferences must be strongly encrypted using SQLCipher, EncryptedSharedPreferences, or AES/GCM.",
        "remediation": "Migrate plaintext SharedPreferences and SQLiteDatabase to androidx.security.crypto.EncryptedSharedPreferences and net.sqlcipher.database.SQLiteDatabase."
    },
    "BB-MFS-02": {
        "clause": "4.1.3.21.b, 6.1.3.17.b, 4.1.1.6",
        "title": "Prohibition of Logging Sensitive Authentication Data (SAD) & CHD",
        "function": "PROTECT",
        "category": "Identity Management & Access Control",
        "severity": "CRITICAL",
        "description": "Card Holder Data (CHD) and Sensitive Authentication Data (SAD) including PIN, OTP, CVV, passwords, or transaction tokens must NEVER be logged via android.util.Log or standard output.",
        "remediation": "Strip all log calls in release builds (using ProGuard/R8) and ensure sensitive parameters are sanitized before entering logging sinks."
    },
    "BB-MFS-03": {
        "clause": "4.1.5.19, 4.1.3.12",
        "title": "Transport Security, Cleartext Prohibition & Certificate Pinning",
        "function": "PROTECT",
        "category": "Data Security & ICT Infrastructure",
        "severity": "HIGH",
        "description": "All network transmissions over WAN/public networks must enforce TLS with trusted certificates. Cleartext HTTP is prohibited, and certificate pinning must be implemented.",
        "remediation": "Set cleartextTrafficPermitted='false' in network_security_config.xml and configure OkHttp CertificatePinner or network security config pin-set."
    },
    "BB-MFS-04": {
        "clause": "4.1.5.19.c, 4.1.5.18",
        "title": "Cryptographic Algorithm Strength & Modern Cipher Suites",
        "function": "PROTECT",
        "category": "Data Security",
        "severity": "HIGH",
        "description": "Cryptographic implementations must use industry-standard algorithms. Deprecated algorithms (DES, 3DES, RC4, MD5, SHA-1) and insecure modes (AES/ECB) are strictly forbidden.",
        "remediation": "Use AES-256 in GCM mode (or CBC with HMAC) and SHA-256/SHA-512 for cryptographic hashing."
    },
    "BB-MFS-05": {
        "clause": "4.1.5.18, 4.1.5.7",
        "title": "Secure Hardware Cryptographic Key Storage",
        "function": "PROTECT",
        "category": "Data Security",
        "severity": "CRITICAL",
        "description": "Cryptographic keys must not be hardcoded in application code or stored in plaintext files. Key material must be protected within the hardware-backed AndroidKeyStore.",
        "remediation": "Generate and store master keys in AndroidKeyStore using KeyGenParameterSpec with PURPOSE_ENCRYPT | PURPOSE_DECRYPT."
    },
    "BB-MFS-06": {
        "clause": "4.1.3.10, 5.1.1.11",
        "title": "Transaction Signing, Non-Repudiation & Anti-Replay Protection",
        "function": "PROTECT & DETECT",
        "category": "ICT Infrastructure & Anomalies",
        "severity": "HIGH",
        "description": "Financial transaction payloads must incorporate cryptographic integrity primitives (digital signatures or HMAC) to prevent alteration, duplication, or replay.",
        "remediation": "Implement java.security.Signature with SHA256withRSA/ECDSA or javax.crypto.Mac with HmacSHA256 on all transaction payloads."
    },
    "BB-MFS-07": {
        "clause": "4.1.5.18, 4.1.5.19",
        "title": "Cryptographically Secure Pseudo-Random Number Generation (PRNG)",
        "function": "PROTECT",
        "category": "Data Security",
        "severity": "MEDIUM",
        "description": "Generation of OTPs, nonces, salt values, and session tokens must use cryptographically secure random number generators (SecureRandom) instead of java.util.Random.",
        "remediation": "Replace all instances of java.util.Random or Math.random() in security-sensitive methods with java.security.SecureRandom."
    },
    "BB-MFS-08": {
        "clause": "4.1.2.5, 4.1.8.4",
        "title": "Principle of Least Privilege & Permission Baseline Adherence",
        "function": "PROTECT",
        "category": "Access Control & Protective Technology",
        "severity": "MEDIUM",
        "description": "MFS applications must request only minimum necessary permissions. Excessive or invasive permissions (e.g. SEND_SMS, READ_CALL_LOG, SYSTEM_ALERT_WINDOW) violate least privilege.",
        "remediation": "Remove unnecessary permissions from AndroidManifest.xml and use Android SMS Retriever API instead of raw SMS read/send permissions."
    },
    "BB-MFS-09": {
        "clause": "4.1.8.10, 4.1.8.6",
        "title": "Hardened Baseline Manifest & Component Configuration",
        "function": "PROTECT",
        "category": "Protective Technology",
        "severity": "HIGH",
        "description": "Application configurations must be hardened against unauthorized access: android:allowBackup must be false, android:debuggable must be false, and exported components must be gated.",
        "remediation": "Set android:allowBackup='false', android:debuggable='false', and ensure all exported activities/receivers declare android:permission."
    },
    "BB-MFS-10": {
        "clause": "4.1.4.4, 5.1.2.19",
        "title": "Source Code Protection, Obfuscation & Anti-Tampering",
        "function": "PROTECT & DETECT",
        "category": "Preventing Unauthorized Software",
        "severity": "MEDIUM",
        "description": "Application source code and business logic must be protected from reverse engineering through identifier renaming, control flow flattening, and metadata stripping.",
        "remediation": "Enable ProGuard / R8 minification and DexGuard anti-tamper protections in build.gradle."
    },
    "BB-MFS-11": {
        "clause": "Appendix C (Items 7, 8, 34)",
        "title": "Embedded Credentials, Hardcoded API Secrets & Private Keys",
        "function": "PROTECT",
        "category": "Security of Hardware, Data & Records",
        "severity": "HIGH",
        "description": "Production API keys, payment gateway credentials, private certificates, and JWT secrets must never be embedded in plaintext inside DEX strings or resource files.",
        "remediation": "Move secrets to secure backend proxies or use dynamic token exchange with AndroidKeyStore protection."
    },
    "BB-MFS-12": {
        "clause": "4.1.4.4, 5.1.2.19",
        "title": "Root, Jailbreak & Execution Environment Integrity Detection",
        "function": "PROTECT & DETECT",
        "category": "System Security & Mobile Defense",
        "severity": "HIGH",
        "description": "Financial applications must actively detect rooted devices, su binaries, test-keys, and hooking frameworks before authorizing sensitive transactions.",
        "remediation": "Implement active root detection (checking /system/bin/su, test-keys, Magisk, or RootBeer) and terminate session if compromised."
    },
    "BB-MFS-13": {
        "clause": "4.1.8.6",
        "title": "Screen Capture, Screenshot & Tapjacking Overlay Protection",
        "function": "PROTECT",
        "category": "Protective Technology",
        "severity": "MEDIUM",
        "description": "Application activities handling authentication and transaction approvals must prevent screen recording and tapjacking overlays using FLAG_SECURE and filterTouchesWhenObscured.",
        "remediation": "Apply getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE) on sensitive payment activities."
    },
    "BB-MFS-14": {
        "clause": "4.1.3.21, 4.1.5.17",
        "title": "Biometric Authentication Cryptographic Object Binding",
        "function": "PROTECT",
        "category": "Access Control & Cryptography",
        "severity": "MEDIUM",
        "description": "Biometric authentication (fingerprint/face) must employ modern AndroidX BiometricPrompt bound to a cryptographic Cipher/Signature (CryptoObject) rather than purely relying on unverified boolean callbacks.",
        "remediation": "Migrate to androidx.biometric.BiometricPrompt and authenticate via BiometricPrompt.CryptoObject backed by AndroidKeyStore."
    }
}

# Fintech Android Permission Baselines for Bangladesh Ecosystem
BENIGN_MFS_PERMISSIONS: Set[str] = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.CAMERA",  # QR Code Scanning
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.RECEIVE_BOOT_COMPLETED"
}

# Functionally Justified Fintech Permissions (Permitted with audit review, e.g. for Agent Locator, P2P Contacts)
FUNCTIONAL_FINTECH_PERMISSIONS: Set[str] = {
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE"
}

# Severe / Invasive Permissions Indicative of Malware, Spyware, or Banking Trojans
INVASIVE_MALWARE_PERMISSIONS: Set[str] = {
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECORD_AUDIO",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE"
}

# Backward compatibility alias
DANGEROUS_MFS_PERMISSIONS = INVASIVE_MALWARE_PERMISSIONS

# Cryptographic and Sensitive Sinks
DEPRECATED_CIPHERS: List[str] = [
    "DES", "DESede", "TripleDES", "RC4", "RC2", "Blowfish", "AES/ECB", "ECB"
]

DEPRECATED_HASHES: List[str] = [
    "MD5", "MD4", "MD2", "SHA-1", "SHA1"
]

# Sensitive Authentication Data (SAD) and Cardholder Data (CHD) keywords
# Excludes benign generic tokens like "token", "balance", "nid" to prevent false positives
SENSITIVE_PARAM_KEYWORDS: List[str] = [
    "user_pin", "pin_code", "login_pin", "card_pin", "wallet_pin",
    "otp_code", "user_otp", "sms_otp", "one_time_password",
    "cvv", "cvv2", "card_number", "pan_number", "credit_card",
    "user_password", "account_password", "passwd", "master_secret"
]

# Shannon Entropy Threshold for Embedded Secrets (bits/character)
HIGH_ENTROPY_THRESHOLD = 4.5
MIN_SECRET_LENGTH = 16
