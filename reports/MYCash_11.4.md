# Regulatory Cybersecurity Audit Report
**Governing Authority**: Bangladesh Bank (Payment Systems Department & ICT Department)
**Regulatory Framework**: Bangladesh Bank Cybersecurity Framework Version 1.0 (February 2025)
**Audit Subject**: `MYCash` (`com.mycash`)
**Audit Scope**: Static Analysis & Machine Learning Evaluation of Android Client Binary
**Date Generated**: September 2026

---
## 1. Executive Summary & Regulatory Classification

| Evaluation Parameter | Result / Metric |
| :--- | :--- |
| **Application Package** | `com.mycash` |
| **Version** | `11.4` (Code: `103`) |
| **Binary Size** | 12.96 MB |
| **Binary SHA-256** | `ea963d5298db7553766b3b9f019516c45c8ee3cb4a05ac184974c6b8228bde03` |
| **Cybersecurity Maturity Score** | **61.0 / 100.0** |
| **Regulatory Classification** | **Tier 3: High Risk (Regulatory Action & Escalation Required)** |

> [!CAUTION]
> **IMMEDIATE REGULATORY ESCALATION REQUIRED (Clause 8.1.2.1)**:
> This application accumulated 0 CRITICAL violations and achieved a Maturity Score below the 70.0 threshold. Under Bangladesh Bank Cybersecurity Framework Clause 8.1.2.1, critical security deficiencies must be escalated and mitigated immediately before public distribution.

---
## 2. Regulatory Clause Audit Breakdown

| Rule ID | Bangladesh Bank Clause | Regulatory Scope | Status | Severity | Penalty |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **BB-MFS-01** | Clause 4.1.5.2, 4.1.5.17, 4.1.5.23 | Encryption of Data at Rest & End-to-End Encryption (E2EE) | ✅ PASSED | `CRITICAL` | -0 |
| **BB-MFS-02** | Clause 4.1.3.21.b, 6.1.3.17.b, 4.1.1.6 | Prohibition of Logging Sensitive Authentication Data (SAD) & CHD | ⚠️ WARNING | `CRITICAL` | -2 |
| **BB-MFS-03** | Clause 4.1.5.19, 4.1.3.12 | Transport Security, Cleartext Prohibition & Certificate Pinning | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-04** | Clause 4.1.5.19.c, 4.1.5.18 | Cryptographic Algorithm Strength & Modern Cipher Suites | ⚠️ WARNING | `HIGH` | -2 |
| **BB-MFS-05** | Clause 4.1.5.18, 4.1.5.7 | Secure Hardware Cryptographic Key Storage | ⚠️ WARNING | `CRITICAL` | -5 |
| **BB-MFS-06** | Clause 4.1.3.10, 5.1.1.11 | Transaction Signing, Non-Repudiation & Anti-Replay Protection | ❌ FAILED | `HIGH` | -10 |
| **BB-MFS-07** | Clause 4.1.5.18, 4.1.5.19 | Cryptographically Secure Pseudo-Random Number Generation (PRNG) | ✅ PASSED | `MEDIUM` | -0 |
| **BB-MFS-08** | Clause 4.1.2.5, 4.1.8.4 | Principle of Least Privilege & Permission Baseline Adherence | ❌ FAILED | `MEDIUM` | -5 |
| **BB-MFS-09** | Clause 4.1.8.10, 4.1.8.6 | Hardened Baseline Manifest & Component Configuration | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-10** | Clause 4.1.4.4, 5.1.2.19 | Source Code Protection, Obfuscation & Anti-Tampering | ✅ PASSED | `MEDIUM` | -0 |
| **BB-MFS-11** | Clause Appendix C (Items 7, 8, 34) | Embedded Credentials, Hardcoded API Secrets & Private Keys | ⚠️ WARNING | `HIGH` | -5 |
| **BB-MFS-12** | Clause 4.1.4.4, 5.1.2.19 | Root, Jailbreak & Execution Environment Integrity Detection | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-13** | Clause 4.1.8.6 | Screen Capture, Screenshot & Tapjacking Overlay Protection | ❌ FAILED | `MEDIUM` | -5 |
| **BB-MFS-14** | Clause 4.1.3.21, 4.1.5.17 | Biometric Authentication Cryptographic Object Binding | ❌ FAILED | `MEDIUM` | -5 |

---
## 3. Detailed Findings & Remediation Directives

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

### [BB-MFS-05] Secure Hardware Cryptographic Key Storage
- **Bangladesh Bank Clause**: `4.1.5.18, 4.1.5.7` (PROTECT - Data Security)
- **Severity**: `CRITICAL` | **Penalty Applied**: `-5 points`
- **Regulatory Observation**: No AndroidKeyStore usage found in client binary.
- **Evidence Findings**:
  * AndroidKeyStore not explicitly detected; verify if keys are stored in backend HSM.
- **Mandated Remediation**: Generate and store master keys in AndroidKeyStore using KeyGenParameterSpec with PURPOSE_ENCRYPT | PURPOSE_DECRYPT.

### [BB-MFS-06] Transaction Signing, Non-Repudiation & Anti-Replay Protection
- **Bangladesh Bank Clause**: `4.1.3.10, 5.1.1.11` (PROTECT & DETECT - ICT Infrastructure & Anomalies)
- **Severity**: `HIGH` | **Penalty Applied**: `-10 points`
- **Regulatory Observation**: Violation of Clause 4.1.3.10: Client application lacks transaction signing mechanisms.
- **Evidence Findings**:
  * No digital signature or HMAC transaction signing primitives detected in client application.
- **Mandated Remediation**: Implement java.security.Signature with SHA256withRSA/ECDSA or javax.crypto.Mac with HmacSHA256 on all transaction payloads.

### [BB-MFS-08] Principle of Least Privilege & Permission Baseline Adherence
- **Bangladesh Bank Clause**: `4.1.2.5, 4.1.8.4` (PROTECT - Access Control & Protective Technology)
- **Severity**: `MEDIUM` | **Penalty Applied**: `-5 points`
- **Regulatory Observation**: Violation of Clause 4.1.2.5 & 4.1.8.4: 2 invasive malware/spyware permissions requested (SYSTEM_ALERT_WINDOW, WRITE_CONTACTS).
- **Evidence Findings**:
  * Severe/Invasive permission violating least privilege: android.permission.SYSTEM_ALERT_WINDOW
  * Severe/Invasive permission violating least privilege: android.permission.WRITE_CONTACTS
- **Mandated Remediation**: Remove unnecessary permissions from AndroidManifest.xml and use Android SMS Retriever API instead of raw SMS read/send permissions.

### [BB-MFS-11] Embedded Credentials, Hardcoded API Secrets & Private Keys
- **Bangladesh Bank Clause**: `Appendix C (Items 7, 8, 34)` (PROTECT - Security of Hardware, Data & Records)
- **Severity**: `HIGH` | **Penalty Applied**: `-5 points`
- **Regulatory Observation**: Potential embedded tokens identified via Shannon entropy heuristics.
- **Evidence Findings**:
  * Suspicious high-entropy string constant (6.00 bits/char): 012...Z-_
    ```
    012...Z-_
    ```
  * Suspicious high-entropy string constant (6.00 bits/char): ABC...9-_
    ```
    ABC...9-_
    ```
  * Suspicious high-entropy string constant (4.50 bits/char): rec...mpl
    ```
    rec...mpl
    ```
- **Mandated Remediation**: Move secrets to secure backend proxies or use dynamic token exchange with AndroidKeyStore protection.

### [BB-MFS-13] Screen Capture, Screenshot & Tapjacking Overlay Protection
- **Bangladesh Bank Clause**: `4.1.8.6` (PROTECT - Protective Technology)
- **Severity**: `MEDIUM` | **Penalty Applied**: `-5 points`
- **Regulatory Observation**: Violation of Clause 4.1.8.6: Missing protection against screen capture and tapjacking overlays.
- **Evidence Findings**:
  * No FLAG_SECURE or filterTouchesWhenObscured configurations identified in bytecode/manifest.
- **Mandated Remediation**: Apply getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE) on sensitive payment activities.

### [BB-MFS-14] Biometric Authentication Cryptographic Object Binding
- **Bangladesh Bank Clause**: `4.1.3.21, 4.1.5.17` (PROTECT - Access Control & Cryptography)
- **Severity**: `MEDIUM` | **Penalty Applied**: `-5 points`
- **Regulatory Observation**: Missing modern biometric authentication framework (BiometricPrompt).
- **Evidence Findings**:
  * No biometric authentication framework (BiometricPrompt) integrated.
- **Mandated Remediation**: Migrate to androidx.biometric.BiometricPrompt and authenticate via BiometricPrompt.CryptoObject backed by AndroidKeyStore.

---
*Report generated by Bangladesh Bank MFS Automated Compliance Framework v1.0.*