# Regulatory Cybersecurity Audit Report
**Governing Authority**: Bangladesh Bank (Payment Systems Department & ICT Department)
**Regulatory Framework**: Bangladesh Bank Cybersecurity Framework Version 1.0 (February 2025)
**Audit Subject**: `Islamic Wallet` (`com.iw.app`)
**Audit Scope**: Static Analysis & Machine Learning Evaluation of Android Client Binary
**Date Generated**: September 2026

---
## 1. Executive Summary & Regulatory Classification

| Evaluation Parameter | Result / Metric |
| :--- | :--- |
| **Application Package** | `com.iw.app` |
| **Version** | `1.0.15` (Code: `17`) |
| **Binary Size** | 18.77 MB |
| **Binary SHA-256** | `3478035f13960cc1ef2fcdd9ee7b0e1befb1ddfe0601868bed99dcd542af7ea5` |
| **Cybersecurity Maturity Score** | **69.0 / 100.0** |
| **Regulatory Classification** | **Tier 3: High Risk (Regulatory Action & Escalation Required)** |

> [!CAUTION]
> **IMMEDIATE REGULATORY ESCALATION REQUIRED (Clause 8.1.2.1)**:
> This application accumulated 1 CRITICAL violations and achieved a Maturity Score below the 70.0 threshold. Under Bangladesh Bank Cybersecurity Framework Clause 8.1.2.1, critical security deficiencies must be escalated and mitigated immediately before public distribution.

---
## 2. Regulatory Clause Audit Breakdown

| Rule ID | Bangladesh Bank Clause | Regulatory Scope | Status | Severity | Penalty |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **BB-MFS-01** | Clause 4.1.5.2, 4.1.5.17, 4.1.5.23 | Encryption of Data at Rest & End-to-End Encryption (E2EE) | ❌ FAILED | `CRITICAL` | -15 |
| **BB-MFS-02** | Clause 4.1.3.21.b, 6.1.3.17.b, 4.1.1.6 | Prohibition of Logging Sensitive Authentication Data (SAD) & CHD | ⚠️ WARNING | `CRITICAL` | -2 |
| **BB-MFS-03** | Clause 4.1.5.19, 4.1.3.12 | Transport Security, Cleartext Prohibition & Certificate Pinning | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-04** | Clause 4.1.5.19.c, 4.1.5.18 | Cryptographic Algorithm Strength & Modern Cipher Suites | ⚠️ WARNING | `HIGH` | -2 |
| **BB-MFS-05** | Clause 4.1.5.18, 4.1.5.7 | Secure Hardware Cryptographic Key Storage | ✅ PASSED | `CRITICAL` | -0 |
| **BB-MFS-06** | Clause 4.1.3.10, 5.1.1.11 | Transaction Signing, Non-Repudiation & Anti-Replay Protection | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-07** | Clause 4.1.5.18, 4.1.5.19 | Cryptographically Secure Pseudo-Random Number Generation (PRNG) | ✅ PASSED | `MEDIUM` | -0 |
| **BB-MFS-08** | Clause 4.1.2.5, 4.1.8.4 | Principle of Least Privilege & Permission Baseline Adherence | ⚠️ WARNING | `MEDIUM` | -2 |
| **BB-MFS-09** | Clause 4.1.8.10, 4.1.8.6 | Hardened Baseline Manifest & Component Configuration | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-10** | Clause 4.1.4.4, 5.1.2.19 | Source Code Protection, Obfuscation & Anti-Tampering | ✅ PASSED | `MEDIUM` | -0 |
| **BB-MFS-11** | Clause Appendix C (Items 7, 8, 34) | Embedded Credentials, Hardcoded API Secrets & Private Keys | ⚠️ WARNING | `HIGH` | -5 |
| **BB-MFS-12** | Clause 4.1.4.4, 5.1.2.19 | Root, Jailbreak & Execution Environment Integrity Detection | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-13** | Clause 4.1.8.6 | Screen Capture, Screenshot & Tapjacking Overlay Protection | ❌ FAILED | `MEDIUM` | -5 |
| **BB-MFS-14** | Clause 4.1.3.21, 4.1.5.17 | Biometric Authentication Cryptographic Object Binding | ✅ PASSED | `MEDIUM` | -0 |

---
## 3. Detailed Findings & Remediation Directives

### [BB-MFS-01] Encryption of Data at Rest & End-to-End Encryption (E2EE)
- **Bangladesh Bank Clause**: `4.1.5.2, 4.1.5.17, 4.1.5.23` (PROTECT - Data Security)
- **Severity**: `CRITICAL` | **Penalty Applied**: `-15 points`
- **Regulatory Observation**: Violation of Clauses 4.1.5.2 and 4.1.5.17: Application uses unencrypted local storage.
- **Evidence Findings**:
  * Detected standard unencrypted SharedPreferences or SQLiteDatabase without SQLCipher or EncryptedSharedPreferences.
- **Mandated Remediation**: Migrate plaintext SharedPreferences and SQLiteDatabase to androidx.security.crypto.EncryptedSharedPreferences and net.sqlcipher.database.SQLiteDatabase.

### [BB-MFS-02] Prohibition of Logging Sensitive Authentication Data (SAD) & CHD
- **Bangladesh Bank Clause**: `4.1.3.21.b, 6.1.3.17.b, 4.1.1.6` (PROTECT - Identity Management & Access Control)
- **Severity**: `CRITICAL` | **Penalty Applied**: `-2 points`
- **Regulatory Observation**: Logging calls present in APK; no obvious plaintext credential log formats found.
- **Evidence Findings**:
  * General android.util.Log calls detected; ensure R8/ProGuard strips them in production.
- **Mandated Remediation**: Strip all log calls in release builds (using ProGuard/R8) and ensure sensitive parameters are sanitized before entering logging sinks.

### [BB-MFS-04] Cryptographic Algorithm Strength & Modern Cipher Suites
- **Bangladesh Bank Clause**: `4.1.5.19.c, 4.1.5.18` (PROTECT - Data Security)
- **Severity**: `HIGH` | **Penalty Applied**: `-2 points`
- **Regulatory Observation**: Advisory under Clause 4.1.5.19.c: Modern crypto verified; legacy hashes detected in dependencies.
- **Evidence Findings**:
  * Legacy hashing primitive in auxiliary/third-party routines: Deprecated Hash: SHA-1
    ```
    Deprecated Hash: SHA-1
    ```
  * Legacy hashing primitive in auxiliary/third-party routines: Deprecated Hash: MD5
    ```
    Deprecated Hash: MD5
    ```
  * Legacy hashing primitive in auxiliary/third-party routines: Deprecated Hash: SHA1
    ```
    Deprecated Hash: SHA1
    ```
- **Mandated Remediation**: Ensure modern SHA-256 is used for all security routines; purge legacy MD5/SHA-1 from dependencies.

### [BB-MFS-08] Principle of Least Privilege & Permission Baseline Adherence
- **Bangladesh Bank Clause**: `4.1.2.5, 4.1.8.4` (PROTECT - Access Control & Protective Technology)
- **Severity**: `MEDIUM` | **Penalty Applied**: `-2 points`
- **Regulatory Observation**: Advisory under Clause 4.1.2.5: 3 functional permissions requested (READ_EXTERNAL_STORAGE, READ_CONTACTS, WRITE_EXTERNAL_STORAGE).
- **Evidence Findings**:
  * Functionally justified permission requiring operational governance: android.permission.READ_EXTERNAL_STORAGE
  * Functionally justified permission requiring operational governance: android.permission.READ_CONTACTS
  * Functionally justified permission requiring operational governance: android.permission.WRITE_EXTERNAL_STORAGE
- **Mandated Remediation**: Ensure functional permissions (e.g. location for agent locator, contacts for recharge) declare explicit in-app runtime consent.

### [BB-MFS-11] Embedded Credentials, Hardcoded API Secrets & Private Keys
- **Bangladesh Bank Clause**: `Appendix C (Items 7, 8, 34)` (PROTECT - Security of Hardware, Data & Records)
- **Severity**: `HIGH` | **Penalty Applied**: `-5 points`
- **Regulatory Observation**: Potential embedded tokens identified via Shannon entropy heuristics.
- **Evidence Findings**:
  * Suspicious high-entropy string constant (4.68 bits/char): $r8...bys
    ```
    $r8...bys
    ```
  * Suspicious high-entropy string constant (4.66 bits/char): $r8...huE
    ```
    $r8...huE
    ```
  * Suspicious high-entropy string constant (4.73 bits/char): $r8...zO0
    ```
    $r8...zO0
    ```
- **Mandated Remediation**: Move secrets to secure backend proxies or use dynamic token exchange with AndroidKeyStore protection.

### [BB-MFS-13] Screen Capture, Screenshot & Tapjacking Overlay Protection
- **Bangladesh Bank Clause**: `4.1.8.6` (PROTECT - Protective Technology)
- **Severity**: `MEDIUM` | **Penalty Applied**: `-5 points`
- **Regulatory Observation**: Violation of Clause 4.1.8.6: Missing protection against screen capture and tapjacking overlays.
- **Evidence Findings**:
  * No FLAG_SECURE or filterTouchesWhenObscured configurations identified in bytecode/manifest.
- **Mandated Remediation**: Apply getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE) on sensitive payment activities.

---
*Report generated by Bangladesh Bank MFS Automated Compliance Framework v1.0.*