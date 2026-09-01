# Regulatory Cybersecurity Audit Report
**Governing Authority**: Bangladesh Bank (Payment Systems Department & ICT Department)
**Regulatory Framework**: Bangladesh Bank Cybersecurity Framework Version 1.0 (February 2025)
**Audit Subject**: `LENDEN` (`com.reddot.lenden.customerapp`)
**Audit Scope**: Static Analysis & Machine Learning Evaluation of Android Client Binary
**Date Generated**: September 2026

---
## 1. Executive Summary & Regulatory Classification

| Evaluation Parameter | Result / Metric |
| :--- | :--- |
| **Application Package** | `com.reddot.lenden.customerapp` |
| **Version** | `2.3.4` (Code: `11142`) |
| **Binary Size** | 66.54 MB |
| **Binary SHA-256** | `2399150b42b1b9cad86a5f992561482fbdfcd9966e06eb76288aa1cc71745a79` |
| **Cybersecurity Maturity Score** | **61.0 / 100.0** |
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
| **BB-MFS-03** | Clause 4.1.5.19, 4.1.3.12 | Transport Security, Cleartext Prohibition & Certificate Pinning | ❌ FAILED | `HIGH` | -10 |
| **BB-MFS-04** | Clause 4.1.5.19.c, 4.1.5.18 | Cryptographic Algorithm Strength & Modern Cipher Suites | ⚠️ WARNING | `HIGH` | -2 |
| **BB-MFS-05** | Clause 4.1.5.18, 4.1.5.7 | Secure Hardware Cryptographic Key Storage | ✅ PASSED | `CRITICAL` | -0 |
| **BB-MFS-06** | Clause 4.1.3.10, 5.1.1.11 | Transaction Signing, Non-Repudiation & Anti-Replay Protection | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-07** | Clause 4.1.5.18, 4.1.5.19 | Cryptographically Secure Pseudo-Random Number Generation (PRNG) | ✅ PASSED | `MEDIUM` | -0 |
| **BB-MFS-08** | Clause 4.1.2.5, 4.1.8.4 | Principle of Least Privilege & Permission Baseline Adherence | ❌ FAILED | `MEDIUM` | -5 |
| **BB-MFS-09** | Clause 4.1.8.10, 4.1.8.6 | Hardened Baseline Manifest & Component Configuration | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-10** | Clause 4.1.4.4, 5.1.2.19 | Source Code Protection, Obfuscation & Anti-Tampering | ✅ PASSED | `MEDIUM` | -0 |
| **BB-MFS-11** | Clause Appendix C (Items 7, 8, 34) | Embedded Credentials, Hardcoded API Secrets & Private Keys | ⚠️ WARNING | `HIGH` | -5 |
| **BB-MFS-12** | Clause 4.1.4.4, 5.1.2.19 | Root, Jailbreak & Execution Environment Integrity Detection | ✅ PASSED | `HIGH` | -0 |
| **BB-MFS-13** | Clause 4.1.8.6 | Screen Capture, Screenshot & Tapjacking Overlay Protection | ✅ PASSED | `MEDIUM` | -0 |
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

### [BB-MFS-03] Transport Security, Cleartext Prohibition & Certificate Pinning
- **Bangladesh Bank Clause**: `4.1.5.19, 4.1.3.12` (PROTECT - Data Security & ICT Infrastructure)
- **Severity**: `HIGH` | **Penalty Applied**: `-10 points`
- **Regulatory Observation**: Violation of Clause 4.1.5.19 & 4.1.3.12: Cleartext transmission or missing/bypassed TLS certificate validation.
- **Evidence Findings**:
  * Insecure cleartext HTTP endpoint: http://ns.adobe.com/exif/1.0/
    ```
    http://ns.adobe.com/exif/1.0/
    ```
  * Insecure cleartext HTTP endpoint: http://javax.xml.XMLConstants/property/accessExternalStylesheet
    ```
    http://javax.xml.XMLConstants/property/accessExternalStylesheet
    ```
  * Insecure cleartext HTTP endpoint: http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/
    ```
    http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/
    ```
  * Insecure cleartext HTTP endpoint: http://ns.adobe.com/camera-raw-settings/1.0/
    ```
    http://ns.adobe.com/camera-raw-settings/1.0/
    ```
  * Insecure cleartext HTTP endpoint: http://www.oracle.com/xml/jaxp/properties/entityExpansionLimit
    ```
    http://www.oracle.com/xml/jaxp/properties/entityExpansionLimit
    ```
- **Mandated Remediation**: Set cleartextTrafficPermitted='false' in network_security_config.xml and configure OkHttp CertificatePinner or network security config pin-set.

### [BB-MFS-04] Cryptographic Algorithm Strength & Modern Cipher Suites
- **Bangladesh Bank Clause**: `4.1.5.19.c, 4.1.5.18` (PROTECT - Data Security)
- **Severity**: `HIGH` | **Penalty Applied**: `-2 points`
- **Regulatory Observation**: Advisory under Clause 4.1.5.19.c: Modern crypto verified; legacy hashes detected in dependencies.
- **Evidence Findings**:
  * Legacy hashing primitive in auxiliary/third-party routines: Deprecated Hash: SHA-1
    ```
    Deprecated Hash: SHA-1
    ```
  * Legacy hashing primitive in auxiliary/third-party routines: Deprecated Hash: sha1
    ```
    Deprecated Hash: sha1
    ```
  * Legacy hashing primitive in auxiliary/third-party routines: Deprecated Hash: SHA1
    ```
    Deprecated Hash: SHA1
    ```
  * Legacy hashing primitive in auxiliary/third-party routines: Deprecated Hash: MD5
    ```
    Deprecated Hash: MD5
    ```
  * Legacy hashing primitive in auxiliary/third-party routines: Deprecated Hash: md5
    ```
    Deprecated Hash: md5
    ```
- **Mandated Remediation**: Ensure modern SHA-256 is used for all security routines; purge legacy MD5/SHA-1 from dependencies.

### [BB-MFS-08] Principle of Least Privilege & Permission Baseline Adherence
- **Bangladesh Bank Clause**: `4.1.2.5, 4.1.8.4` (PROTECT - Access Control & Protective Technology)
- **Severity**: `MEDIUM` | **Penalty Applied**: `-5 points`
- **Regulatory Observation**: Violation of Clause 4.1.2.5 & 4.1.8.4: 1 invasive malware/spyware permissions requested (RECORD_AUDIO).
- **Evidence Findings**:
  * Severe/Invasive permission violating least privilege: android.permission.RECORD_AUDIO
- **Mandated Remediation**: Remove unnecessary permissions from AndroidManifest.xml and use Android SMS Retriever API instead of raw SMS read/send permissions.

### [BB-MFS-11] Embedded Credentials, Hardcoded API Secrets & Private Keys
- **Bangladesh Bank Clause**: `Appendix C (Items 7, 8, 34)` (PROTECT - Security of Hardware, Data & Records)
- **Severity**: `HIGH` | **Penalty Applied**: `-5 points`
- **Regulatory Observation**: Potential embedded tokens identified via Shannon entropy heuristics.
- **Evidence Findings**:
  * Suspicious high-entropy string constant (4.68 bits/char): $r8...bys
    ```
    $r8...bys
    ```
  * Suspicious high-entropy string constant (4.73 bits/char): $r8...zO0
    ```
    $r8...zO0
    ```
  * Suspicious high-entropy string constant (4.51 bits/char): get...zes
    ```
    get...zes
    ```
- **Mandated Remediation**: Move secrets to secure backend proxies or use dynamic token exchange with AndroidKeyStore protection.

---
*Report generated by Bangladesh Bank MFS Automated Compliance Framework v1.0.*