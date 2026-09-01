"""
Dataset Builder, Synthetic Perturbation Generator, and Small-Data Augmentation.
"""

import os
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple, Optional, Any
from mfs_checker.ml.feature_extractor import MFSFeatureExtractor

class MFSDatasetBuilder:
    """Manages feature matrices, compliance labels, and synthetic augmentation."""

    def __init__(self, feature_extractor: Optional[MFSFeatureExtractor] = None):
        self.extractor = feature_extractor or MFSFeatureExtractor()
        self.feature_names = self.extractor.get_feature_names()

    def generate_synthetic_fintech_dataset(
        self,
        n_compliant: int = 25,
        n_non_compliant: int = 25,
        random_seed: int = 42
    ) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
        """
        Generate mathematically realistic fintech feature profiles for Bangladesh MFS ecosystem.
        Returns:
            X (DataFrame): [N, 42] feature matrix
            y_compliant (Series): Binary compliant/non-compliant label (1=Compliant, 0=Non-Compliant)
            y_scores (Series): Continuous Bangladesh Bank Maturity Score (0-100)
        """
        np.random.seed(random_seed)
        rows = []
        labels = []
        scores = []

        # 1. Compliant Fintech Apps (e.g. bKash, Nagad, Upay, CellFin with proper security)
        for i in range(n_compliant):
            row = {}
            # Standard benign permissions
            row["perm_internet"] = 1.0
            row["perm_access_network_state"] = 1.0
            row["perm_access_wifi_state"] = 1.0
            row["perm_camera"] = 1.0 if np.random.rand() > 0.1 else 0.0
            row["perm_use_biometric"] = 1.0 if np.random.rand() > 0.15 else 0.0
            row["perm_use_fingerprint"] = 1.0 if np.random.rand() > 0.15 else 0.0

            # Low dangerous permissions (strictly bounded)
            for p in ["send_sms", "read_sms", "receive_sms", "read_call_log", "write_call_log",
                      "process_outgoing_calls", "record_audio", "system_alert_window",
                      "write_settings", "access_fine_location", "access_coarse_location",
                      "read_contacts", "write_contacts", "read_external_storage"]:
                row[f"perm_{p}"] = 1.0 if np.random.rand() < 0.05 else 0.0

            # Strong security APIs
            row["api_cipher"] = float(np.random.uniform(2.0, 4.5))
            row["api_encrypted_storage"] = float(np.random.uniform(1.5, 3.5))
            row["api_plain_db"] = float(np.random.uniform(0.0, 1.0))
            row["api_plain_prefs"] = float(np.random.uniform(0.0, 1.5))
            row["api_log_calls"] = float(np.random.uniform(0.0, 1.0))
            row["api_cert_pinner"] = float(np.random.uniform(1.2, 3.0))
            row["api_trust_manager"] = float(np.random.uniform(1.0, 2.5))
            row["api_keystore"] = float(np.random.uniform(1.5, 3.2))
            row["api_signature"] = float(np.random.uniform(1.0, 2.8))
            row["api_secure_random"] = float(np.random.uniform(1.5, 3.0))
            row["api_insecure_random"] = 0.0
            row["api_weak_crypto"] = 0.0
            row["api_root_detection"] = float(np.random.uniform(1.0, 3.0))
            row["api_screen_protection"] = float(np.random.uniform(1.0, 2.0))
            row["api_biometric_prompt"] = float(np.random.uniform(1.0, 2.5))

            # Secure Manifest
            row["mf_allow_backup"] = 0.0
            row["mf_debuggable"] = 0.0
            row["mf_uses_cleartext"] = 0.0
            row["mf_exported_components"] = float(np.random.randint(1, 4))
            row["mf_total_permissions"] = float(sum(v for k, v in row.items() if k.startswith("perm_")))

            # Obfuscation & Complexity
            row["code_total_classes"] = float(np.random.randint(1500, 4500))
            row["code_total_strings"] = float(np.random.randint(8000, 25000))
            row["code_mean_string_entropy"] = float(np.random.uniform(3.8, 4.4))
            row["code_max_string_entropy"] = float(np.random.uniform(4.8, 5.6))
            row["code_obfuscation_ratio"] = float(np.random.uniform(0.65, 0.92))

            rows.append(row)
            labels.append(1)  # Compliant
            scores.append(float(np.random.uniform(86.0, 98.0)))

        # 2. Non-Compliant / Flawed / Rogue Apps (insecure storage, missing cert pin, dangerous perms)
        for i in range(n_non_compliant):
            row = {}
            row["perm_internet"] = 1.0
            row["perm_access_network_state"] = 1.0
            row["perm_access_wifi_state"] = 1.0
            row["perm_camera"] = 1.0 if np.random.rand() > 0.5 else 0.0
            row["perm_use_biometric"] = 0.0
            row["perm_use_fingerprint"] = 0.0

            # High dangerous permissions
            for p in ["send_sms", "read_sms", "receive_sms", "read_call_log", "write_call_log",
                      "process_outgoing_calls", "record_audio", "system_alert_window",
                      "write_settings", "access_fine_location", "access_coarse_location",
                      "read_contacts", "write_contacts", "read_external_storage"]:
                row[f"perm_{p}"] = 1.0 if np.random.rand() < 0.45 else 0.0

            # Weak/Plaintext Storage, Missing Keystore, Weak Crypto
            row["api_cipher"] = float(np.random.uniform(0.0, 1.5))
            row["api_encrypted_storage"] = 0.0
            row["api_plain_db"] = float(np.random.uniform(2.0, 4.0))
            row["api_plain_prefs"] = float(np.random.uniform(2.5, 4.5))
            row["api_log_calls"] = float(np.random.uniform(2.5, 5.0))
            row["api_cert_pinner"] = 0.0
            row["api_trust_manager"] = float(np.random.uniform(0.0, 1.0))
            row["api_keystore"] = 0.0
            row["api_signature"] = 0.0
            row["api_secure_random"] = 0.0
            row["api_insecure_random"] = float(np.random.uniform(1.5, 3.5))
            row["api_weak_crypto"] = float(np.random.uniform(1.0, 3.0))
            row["api_root_detection"] = 0.0
            row["api_screen_protection"] = 0.0
            row["api_biometric_prompt"] = 0.0

            # Insecure Manifest
            row["mf_allow_backup"] = 1.0 if np.random.rand() > 0.3 else 0.0
            row["mf_debuggable"] = 1.0 if np.random.rand() > 0.7 else 0.0
            row["mf_uses_cleartext"] = 1.0 if np.random.rand() > 0.4 else 0.0
            row["mf_exported_components"] = float(np.random.randint(5, 18))
            row["mf_total_permissions"] = float(sum(v for k, v in row.items() if k.startswith("perm_")))

            # Obfuscation & Complexity (Often unminified or weakly obfuscated)
            row["code_total_classes"] = float(np.random.randint(300, 1200))
            row["code_total_strings"] = float(np.random.randint(1500, 6000))
            row["code_mean_string_entropy"] = float(np.random.uniform(3.2, 3.7))
            row["code_max_string_entropy"] = float(np.random.uniform(4.0, 4.7))
            row["code_obfuscation_ratio"] = float(np.random.uniform(0.05, 0.25))

            rows.append(row)
            labels.append(0)  # Non-Compliant
            scores.append(float(np.random.uniform(30.0, 68.0)))

        df = pd.DataFrame(rows)[self.feature_names]
        return df, pd.Series(labels, name="compliant"), pd.Series(scores, name="maturity_score")
