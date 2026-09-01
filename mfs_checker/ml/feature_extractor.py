"""
Dense 42-Dimensional Feature Extractor for MFS Android Applications.
"""

import math
import re
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

# Standard fintech feature dimensions
FEATURE_PERMISSIONS = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CAMERA",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECORD_AUDIO",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE"
]

FEATURE_API_KEYWORDS = [
    ("api_cipher", ["Cipher;->getInstance", "Cipher.getInstance"]),
    ("api_encrypted_storage", ["EncryptedSharedPreferences", "MasterKey", "SQLCipher"]),
    ("api_plain_db", ["SQLiteDatabase", "SQLiteOpenHelper"]),
    ("api_plain_prefs", ["getSharedPreferences"]),
    ("api_log_calls", ["Log;->d", "Log;->v", "Log;->i", "Log;->e", "System.out"]),
    ("api_cert_pinner", ["CertificatePinner", "pin-set"]),
    ("api_trust_manager", ["X509TrustManager", "checkServerTrusted"]),
    ("api_keystore", ["AndroidKeyStore", "KeyStore.getInstance"]),
    ("api_signature", ["java/security/Signature", "javax/crypto/Mac", "HmacSHA256"]),
    ("api_secure_random", ["SecureRandom"]),
    ("api_insecure_random", ["java/util/Random", "Math.random"]),
    ("api_weak_crypto", ["DES", "AES/ECB", "MD5", "SHA-1"]),
    ("api_root_detection", ["rootbeer", "/system/bin/su", "which su", "test-keys"]),
    ("api_screen_protection", ["FLAG_SECURE", "filterTouchesWhenObscured"]),
    ("api_biometric_prompt", ["BiometricPrompt", "CryptoObject"])
]

class MFSFeatureExtractor:
    """Extracts standardized, normalized numerical features from an APK for ML tasks."""

    def __init__(self):
        self.feature_names = self._build_feature_names()

    def _build_feature_names(self) -> List[str]:
        names = []
        # 1. Permissions (20)
        for perm in FEATURE_PERMISSIONS:
            names.append(f"perm_{perm.split('.')[-1].lower()}")
        # 2. API Frequencies (12)
        for key, _ in FEATURE_API_KEYWORDS:
            names.append(key)
        # 3. Manifest metrics (5)
        names.extend([
            "mf_allow_backup",
            "mf_debuggable",
            "mf_uses_cleartext",
            "mf_exported_components",
            "mf_total_permissions"
        ])
        # 4. Complexity & Entropy (5)
        names.extend([
            "code_total_classes",
            "code_total_strings",
            "code_mean_string_entropy",
            "code_max_string_entropy",
            "code_obfuscation_ratio"
        ])
        return names

    def get_feature_names(self) -> List[str]:
        return list(self.feature_names)

    @staticmethod
    def _entropy(text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return - sum(p * math.log2(p) for p in prob)

    def extract_from_objects(self, apk_obj: Any, dex_list: List[Any], analysis_obj: Any) -> Tuple[np.ndarray, Dict[str, float]]:
        features: Dict[str, float] = {}

        # 1. Permissions Extraction (Binary 0 or 1)
        req_perms = set()
        if hasattr(apk_obj, "get_permissions"):
            try:
                for p in apk_obj.get_permissions():
                    req_perms.add(str(p))
            except Exception:
                pass
        elif hasattr(apk_obj, "permissions"):
            req_perms = set(getattr(apk_obj, "permissions", []))

        for perm in FEATURE_PERMISSIONS:
            features[f"perm_{perm.split('.')[-1].lower()}"] = 1.0 if perm in req_perms else 0.0

        # 2. Extract DEX Strings
        strings = []
        if analysis_obj and hasattr(analysis_obj, "get_strings"):
            try:
                for s in analysis_obj.get_strings():
                    val = getattr(s, "get_value", lambda: str(s))()
                    if isinstance(val, str):
                        strings.append(val)
            except Exception:
                pass
        if not strings and dex_list:
            for dex in dex_list:
                if hasattr(dex, "get_strings"):
                    try:
                        for s in dex.get_strings():
                            if isinstance(s, str):
                                strings.append(s)
                    except Exception:
                        pass

        all_text = " ".join(strings)

        # Count API Frequencies (log-scaled: log1p(count))
        for key, patterns in FEATURE_API_KEYWORDS:
            cnt = sum(all_text.count(pat) for pat in patterns)
            features[key] = float(np.log1p(cnt))

        # 3. Manifest Metrics
        manifest_str = ""
        if hasattr(apk_obj, "get_android_manifest_xml"):
            try:
                xml_obj = apk_obj.get_android_manifest_xml()
                if xml_obj is not None:
                    import xml.etree.ElementTree as ET
                    manifest_str = ET.tostring(xml_obj, encoding="unicode")
            except Exception:
                pass
        if not manifest_str and hasattr(apk_obj, "xml"):
            manifest_str = str(getattr(apk_obj, "xml", ""))

        features["mf_allow_backup"] = 1.0 if 'android:allowBackup="true"' in manifest_str else 0.0
        features["mf_debuggable"] = 1.0 if 'android:debuggable="true"' in manifest_str else 0.0
        features["mf_uses_cleartext"] = 1.0 if 'android:usesCleartextTraffic="true"' in manifest_str else 0.0
        features["mf_exported_components"] = float(manifest_str.count('android:exported="true"'))
        features["mf_total_permissions"] = float(len(req_perms))

        # 4. Complexity & Entropy
        classes = []
        if analysis_obj and hasattr(analysis_obj, "get_classes"):
            try:
                for c in analysis_obj.get_classes():
                    classes.append(str(getattr(c, "name", "")))
            except Exception:
                pass

        features["code_total_classes"] = float(len(classes))
        features["code_total_strings"] = float(len(strings))

        if strings:
            # Sample up to 500 strings for entropy distribution
            sampled = strings[:500]
            entropies = [self._entropy(s) for s in sampled if len(s) >= 4]
            features["code_mean_string_entropy"] = float(np.mean(entropies)) if entropies else 0.0
            features["code_max_string_entropy"] = float(np.max(entropies)) if entropies else 0.0
        else:
            features["code_mean_string_entropy"] = 0.0
            features["code_max_string_entropy"] = 0.0

        # Obfuscation ratio
        obf_count = 0
        total_app_cls = 0
        sdk_prefixes = [
            "Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/", "Ljava/", "Ljavax/",
            "Lcom/google/", "Lcom/facebook/", "Lcom/alibaba/", "Lio/flutter/", "Lio/reactivex/",
            "Lokio/", "Lokhttp3/", "Lorg/"
        ]
        for c in classes:
            if any(c.startswith(pfx) for pfx in sdk_prefixes):
                continue
            total_app_cls += 1
            parts = c.strip("L;").split("/")
            if parts and (len(parts[-1]) <= 2 or len(parts[0]) <= 2 or (len(parts) > 1 and len(parts[1]) <= 2)):
                obf_count += 1
        features["code_obfuscation_ratio"] = float(obf_count / total_app_cls) if total_app_cls > 0 else 0.0

        # Convert to numpy array in strict canonical order
        vector = np.array([features[fname] for fname in self.feature_names], dtype=np.float32)
        return vector, features

    def extract_from_apk(self, apk_path: str) -> Tuple[np.ndarray, Dict[str, float]]:
        """Extract features directly from an APK or .apks bundle file path."""
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
            return self.extract_from_objects(apk_obj, dex_list, analysis_obj)
        finally:
            if temp_dir:
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass
