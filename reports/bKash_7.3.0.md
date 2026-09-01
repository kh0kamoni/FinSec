# Regulatory Cybersecurity Audit Report
**Governing Authority**: Bangladesh Bank (Payment Systems Department & ICT Department)
**Regulatory Framework**: Bangladesh Bank Cybersecurity Framework Version 1.0 (February 2025)
**Audit Subject**: `bKash` (`com.bKash.customerapp`)
**Audit Scope**: Static Analysis & Machine Learning Evaluation of Android Client Binary
**Date Generated**: September 2026

---
## 1. Executive Summary & Regulatory Classification

| Evaluation Parameter | Result / Metric |
| :--- | :--- |
| **Application Package** | `com.bKash.customerapp` |
| **Version** | `7.3.0` (Code: `39008719`) |
| **Binary Size** | 77.76 MB |
| **Binary SHA-256** | `bb2f194421a325b6f09ba984bb5e237d5abad8c0fc5a23c730a6658d99a9fb38` |
| **Cybersecurity Maturity Score** | **73.0 / 100.0** |
| **Regulatory Classification** | **Tier 2: Substantially Compliant (Remediation Required)** |

> [!WARNING]
> **SUBSTANTIALLY COMPLIANT - REMEDIATION REQUIRED**:
> The application demonstrates baseline security mechanisms, but non-critical compliance gaps exist. Remediation should be verified in the next development cycle.

---
## 2. Regulatory Clause Audit Breakdown

| Rule ID | Bangladesh Bank Clause | Regulatory Scope | Status | Severity | Penalty |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **BB-MFS-01** | Clause 4.1.5.2, 4.1.5.17, 4.1.5.23 | Encryption of Data at Rest & End-to-End Encryption (E2EE) | ✅ PASSED | `CRITICAL` | -0 |
| **BB-MFS-02** | Clause 4.1.3.21.b, 6.1.3.17.b, 4.1.1.6 | Prohibition of Logging Sensitive Authentication Data (SAD) & CHD | ⚠️ WARNING | `CRITICAL` | -2 |
| **BB-MFS-03** | Clause 4.1.5.19, 4.1.3.12 | Transport Security, Cleartext Prohibition & Certificate Pinning | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-04** | Clause 4.1.5.19.c, 4.1.5.18 | Cryptographic Algorithm Strength & Modern Cipher Suites | ❌ FAILED | `HIGH` | -10 |
| **BB-MFS-05** | Clause 4.1.5.18, 4.1.5.7 | Secure Hardware Cryptographic Key Storage | ✅ PASSED | `CRITICAL` | -0 |
| **BB-MFS-06** | Clause 4.1.3.10, 5.1.1.11 | Transaction Signing, Non-Repudiation & Anti-Replay Protection | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-07** | Clause 4.1.5.18, 4.1.5.19 | Cryptographically Secure Pseudo-Random Number Generation (PRNG) | ✅ PASSED | `MEDIUM` | -0 |
| **BB-MFS-08** | Clause 4.1.2.5, 4.1.8.4 | Principle of Least Privilege & Permission Baseline Adherence | ❌ FAILED | `MEDIUM` | -5 |
| **BB-MFS-09** | Clause 4.1.8.10, 4.1.8.6 | Hardened Baseline Manifest & Component Configuration | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-10** | Clause 4.1.4.4, 5.1.2.19 | Source Code Protection, Obfuscation & Anti-Tampering | ✅ PASSED | `MEDIUM` | -0 |
| **BB-MFS-11** | Clause Appendix C (Items 7, 8, 34) | Embedded Credentials, Hardcoded API Secrets & Private Keys | ⚠️ WARNING | `HIGH` | -5 |
| **BB-MFS-12** | Clause 4.1.4.4, 5.1.2.19 | Root, Jailbreak & Execution Environment Integrity Detection | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-13** | Clause 4.1.8.6 | Screen Capture, Screenshot & Tapjacking Overlay Protection | ❌ FAILED | `MEDIUM` | -5 |
| **BB-MFS-14** | Clause 4.1.3.21, 4.1.5.17 | Biometric Authentication Cryptographic Object Binding | ✅ PASSED | `MEDIUM` | -0 |

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
- **Severity**: `HIGH` | **Penalty Applied**: `-10 points`
- **Regulatory Observation**: Violation of Clause 4.1.5.19.c: Found 4 insecure ciphers (e.g. DES, RC4, ECB).
- **Evidence Findings**:
  * Insecure cipher algorithm detected: Insecure Cipher: AES/ECB/NoPadding
    ```
    Insecure Cipher: AES/ECB/NoPadding
    ```
  * Insecure cipher algorithm detected: Insecure Cipher: AES/ECB/NOPADDING
    ```
    Insecure Cipher: AES/ECB/NOPADDING
    ```
  * Insecure cipher algorithm detected: Insecure Cipher: DESede
    ```
    Insecure Cipher: DESede
    ```
  * Insecure cipher algorithm detected: Insecure Cipher: ECB
    ```
    Insecure Cipher: ECB
    ```
- **Mandated Remediation**: Use AES-256 in GCM mode (or CBC with HMAC) and SHA-256/SHA-512 for cryptographic hashing.

### [BB-MFS-08] Principle of Least Privilege & Permission Baseline Adherence
- **Bangladesh Bank Clause**: `4.1.2.5, 4.1.8.4` (PROTECT - Access Control & Protective Technology)
- **Severity**: `MEDIUM` | **Penalty Applied**: `-5 points`
- **Regulatory Observation**: Violation of Clause 4.1.2.5 & 4.1.8.4: 2 invasive malware/spyware permissions requested (WRITE_CONTACTS, RECORD_AUDIO).
- **Evidence Findings**:
  * Severe/Invasive permission violating least privilege: android.permission.WRITE_CONTACTS
  * Severe/Invasive permission violating least privilege: android.permission.RECORD_AUDIO
- **Mandated Remediation**: Remove unnecessary permissions from AndroidManifest.xml and use Android SMS Retriever API instead of raw SMS read/send permissions.

### [BB-MFS-11] Embedded Credentials, Hardcoded API Secrets & Private Keys
- **Bangladesh Bank Clause**: `Appendix C (Items 7, 8, 34)` (PROTECT - Security of Hardware, Data & Records)
- **Severity**: `HIGH` | **Penalty Applied**: `-5 points`
- **Regulatory Observation**: Potential embedded tokens identified via Shannon entropy heuristics.
- **Evidence Findings**:
  * Suspicious high-entropy string constant (4.65 bits/char): H16...A==
    ```
    H16...A==
    ```
  * Suspicious high-entropy string constant (4.68 bits/char): BmC...w==
    ```
    BmC...w==
    ```
  * Suspicious high-entropy string constant (4.78 bits/char): dBS...jE=
    ```
    dBS...jE=
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