# FinSec: Static Analysis of Android Binaries for Compliance Against Bangladesh Bank Cybersecurity Framework v1.0

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-18%20passed-success.svg)](tests/)
[![Compliance Standard](https://img.shields.io/badge/Standard-Bangladesh_Bank_v1.0_(Feb_2025)-crimson.svg)](https://www.bb.org.bd)

An automated static analysis and machine learning framework for evaluating Mobile Financial Services (MFS) and Payment Service Provider (PSP) Android applications against the **Bangladesh Bank Cybersecurity Framework Version 1.0 (February 2025)**.

---

## 1. Overview & Regulatory Grounding

In February 2025, Bangladesh Bank issued its official **Cybersecurity Framework Version 1.0**, establishing mandatory technical controls for all regulated financial institutions, specifically including:
* **Mobile Financial Service Providers (MFSPs)** (e.g., bKash, Nagad, Rocket, Upay)
* **Payment Service Providers (PSPs)** and **Payment System Operators (PSOs)**
* **Scheduled Commercial Banks and NBFIs** (e.g., Islami Bank / mCash, Southeast Bank / TeleCash)

This framework translates policy mandates into automated Dalvik bytecode and AndroidManifest verification rules, coupled with a **45-dimensional machine learning pipeline** tailored for bounded national application populations ($N \approx 12\text{--}25$).

```mermaid
flowchart TD
    subgraph Input["Input Tier"]
        APK[Android MFS APK]
    end

    subgraph StaticCore["Static Auditing Engine (Androguard)"]
        Parser[DEX & Manifest Parser]
        Rules[14 BB-MFS Verification Rules]
        ScoreCalc[0-100 Maturity Index Calculator]
    end

    subgraph MLPipeline["Machine Learning Pipeline"]
        FE[45-Dimensional Multimodal Feature Extractor]
        LOOCV[Leave-One-Out Cross-Validation Pipeline]
        Regressor[Ridge Score Regressor (LOOCV R²=0.4258)]
        Anomaly[Isolation Forest Anomaly Triage]
    end

    subgraph Reporting["Reporting & Audit Tier"]
        Console[Rich Color Terminal Dashboard]
        Markdown[BB Clause 8.1.3 Markdown Audit Report]
        JSON[Structured CI/CD & SIEM JSON]
    end

    APK --> Parser
    Parser --> Rules
    Parser --> FE
    Rules --> ScoreCalc
    FE --> LOOCV
    FE --> Regressor
    FE --> Anomaly
    ScoreCalc --> Console
    ScoreCalc --> Markdown
    ScoreCalc --> JSON
    LOOCV --> Markdown
    Anomaly --> Markdown
```

---

## 2. Regulatory Clause Mapping Matrix (14 Enforceable Rules)

| Rule ID | Bangladesh Bank Clause | Scope & Title | Severity | Penalty | Static Verification Logic |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **BB-MFS-01** | 4.1.5.2, 4.1.5.17 | Encryption of Data at Rest & E2EE | **CRITICAL** | -15 | Verifies `EncryptedSharedPreferences`, `MasterKey`, `flutter_secure_storage`, or `SQLCipher`. Flags plaintext storage. |
| **BB-MFS-02** | 4.1.3.21.b, 6.1.3.17.b | Prohibition of Logging Sensitive Authentication Data (SAD) | **CRITICAL** | -15 | Inspects `Log.d`, `Log.i`, and print calls for PIN, OTP, CVV, or card numbers. Flags unstripped release logging. |
| **BB-MFS-03** | 4.1.5.19, 4.1.3.12 | Transport Security & Certificate Pinning | **HIGH** | -10 | Flags `usesCleartextTraffic="true"`, HTTP endpoints, and permissive `TrustManager`. Verifies `CertificatePinner`. |
| **BB-MFS-04** | 4.1.5.19.c, 4.1.5.18 | Deprecation of Insecure Cryptography | **HIGH** | -10 | Flags broken ciphers (`DES`, `RC4`, `AES/ECB`) and weak hashes (`MD5`, `SHA-1`). Verifies AES-GCM and SHA-256. |
| **BB-MFS-05** | 4.1.5.18, 4.1.5.7 | Hardware KeyStore Key Isolation | **CRITICAL** | -15 | Flags hardcoded `SecretKeySpec` byte arrays. Verifies integration of hardware-backed `AndroidKeyStore`. |
| **BB-MFS-06** | 4.1.3.10, 5.1.1.11 | Transaction Signing & Integrity Verification | **HIGH** | -10 | Verifies digital signature verification (`Signature`) or HMAC validation (`Mac` with SHA-256) on payment payloads. |
| **BB-MFS-07** | 4.1.5.18, 4.1.5.19 | Cryptographically Secure PRNG | **MEDIUM** | -5 | Flags predictable `java.util.Random` in security-critical paths. Confirms `java.security.SecureRandom`. |
| **BB-MFS-08** | 4.1.2.5, 4.1.8.4 | Principle of Least Privilege (Permissions) | **MEDIUM** | -5 | Flags invasive malware permissions (`SEND_SMS`, `READ_CALL_LOG`, `SYSTEM_ALERT_WINDOW`, `RECORD_AUDIO`). |
| **BB-MFS-09** | 4.1.8.10, 4.1.8.6 | Hardened Manifest & Export Protection | **HIGH** | -10 | Flags `allowBackup="true"`, `debuggable="true"`, and unprotected exported activities/services. |
| **BB-MFS-10** | 4.1.4.4, 5.1.2.19 | Code Obfuscation & Source Protection | **MEDIUM** | -5 | Evaluates package/class identifier entropy; flags unminified business logic; computes obfuscation ratio $\Omega(A)$. |
| **BB-MFS-11** | Appendix C (7, 8, 34) | High-Entropy Credentials & Secret Leakage | **HIGH** | -10 | Flags embedded AWS credentials, Google API keys, JWT secrets, and high-entropy ($H \ge 4.5$) string literals. |
| **BB-MFS-12** | 4.1.4.4, 5.1.2.19 | Environment Integrity & Root Detection | **HIGH** | -10 | Scans for active root detection (`/system/bin/su`, `test-keys`, Magisk, RootBeer library integration). |
| **BB-MFS-13** | 4.1.8.6 | Screen Capture & Tapjacking Shielding | **MEDIUM** | -5 | Verifies enforcement of `FLAG_SECURE` and `filterTouchesWhenObscured="true"` on transaction screens. |
| **BB-MFS-14** | 4.1.3.21, 4.1.5.17 | Biometric Cryptographic Binding | **MEDIUM** | -5 | Confirms `BiometricPrompt` authenticated via hardware KeyStore `CryptoObject` rather than raw boolean callbacks. |

---

## 3. Installation & Setup

### Prerequisites
* Python 3.10 or higher
* Java Runtime Environment (JRE 11+) for decompilation backend (optional, bundled via Androguard)

### Setup
```bash
# Clone the repository
git clone https://github.com/kh0kamoni/FinSec.git
cd FinSec

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1

# Install package and dependencies
pip install -r requirements.txt
pip install -e .
```

---

## 4. CLI Usage

The framework provides a unified command line tool: `mfs-check` (or `python -m mfs_checker.cli`).

### 1. Audit a Single APK
```bash
# Run a full compliance audit and export reports
mfs-check scan path/to/app.apk --markdown audit_report.md --json audit_report.json
```

### 2. Batch Audit an Entire Directory of APKs
```bash
# Analyze all production APKs in a folder and generate a summary scorecard
mfs-check batch path/to/apk_folder/ --output results/summary.csv
```

### 3. Machine Learning Evaluation
```bash
# Run Leave-One-Out Cross-Validation (LOOCV), feature importance ranking, and anomaly detection
python experiments/run_real_empirical_analysis.py
```

---

## 5. Regulatory Classification Tiers

The continuous **Cybersecurity Maturity Score** $S(A) \in [0, 100]$ is computed as:
$$S(A) = \max\left(0, 100 - \sum_{i=1}^{14} w_i \cdot \mathbb{I}(s_i = \text{FAILED}) - \sum_{j=1}^{14} \min(w_j, 2) \cdot \mathbb{I}(s_j = \text{WARNING})\right)$$

Applications are classified into central bank regulatory tiers:
* **Tier 1 (Compliant)**: Score $\ge 85.0$ and $C_{\text{crit}} = 0$. Eligible for unconditional production operation.
* **Tier 2 (Conditional)**: Score $70.0\text{--}84.9$ and $C_{\text{crit}} = 0$. Remediation required within 90 days.
* **Tier 3 (High Risk)**: Score $< 70.0$ or $C_{\text{crit}} \ge 1$. Triggers mandatory 72-hour regulatory notification per BB Clause 8.1.2.1.

---

## 6. Running Automated Tests

Run the complete test suite verifying all 14 static rules, the 45-dimensional feature extractor, and machine learning components:
```bash
pytest -v
```
* **18 passing unit tests** executing in `< 3.5s`.

---

## 7. Project Structure

```
mfs_ml/
├── mfs_checker/               # Core Python static auditing and ML package
│   ├── rules/                 # 14 BB-MFS static verification rules
│   │   ├── base.py            # Base rule class and multi-DEX string extractor
│   │   ├── storage.py         # BB-MFS-01: EncryptedSharedPreferences / SQLCipher
│   │   ├── logging.py         # BB-MFS-02: SAD credential leak detection
│   │   ├── crypto.py          # BB-MFS-03 & 04: TLS, cipher suites, certificate pinning
│   │   ├── keystore.py        # BB-MFS-05 & 06: AndroidKeyStore and transaction signing
│   │   ├── permissions.py     # BB-MFS-07 & 08: PRNG and least-privilege permissions
│   │   ├── manifest.py        # BB-MFS-09: Hardened manifest configuration
│   │   ├── obfuscation.py     # BB-MFS-10: Class entropy and obfuscation ratio
│   │   ├── secrets.py         # BB-MFS-11: Shannon entropy and cloud API keys
│   │   ├── root.py            # BB-MFS-12: Root detection and environment integrity
│   │   ├── screen.py          # BB-MFS-13: FLAG_SECURE and overlay protection
│   │   └── biometric.py       # BB-MFS-14: BiometricPrompt CryptoObject binding
│   ├── cli.py                 # Unified CLI interface (scan, batch, evaluate)
│   ├── config.py              # Bangladesh Bank regulatory parameters and weights
│   ├── engine.py              # Audit orchestration engine and scoring calculator
│   ├── features.py            # 45-dimensional multimodal feature extractor
│   ├── models.py              # LOOCV Ridge regressor and Isolation Forest
│   └── reporter.py            # Markdown, JSON, and Rich terminal reporting
├── experiments/               # Empirical experiment runner
│   └── run_real_empirical_analysis.py
├── results/                   # Empirical census scorecards and feature matrices
│   ├── mfs_audit_summary.csv
│   └── mfs_features_real.csv
├── tests/                     # Automated test suite (18 unit tests)
├── LICENSE                    # Apache License 2.0
├── pyproject.toml             # Standard Python packaging configuration
├── requirements.txt           # Dependency specifications
└── README.md                  # Comprehensive framework documentation
```

---

## 8. License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

---

## 9. Citation

If you use this framework or empirical findings in your research, please cite:
```bibtex
@article{finsec2026,
  title   = {FinSec: Static Analysis of Android Binaries for Compliance Against Bangladesh Bank Cybersecurity Framework v1.0},
  author  = {Anonymous Author(s)},
  journal = {Proceedings of the International Conference on Networking, Systems and Security (NSysS)},
  year    = {2026}
}
```
