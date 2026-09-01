"""
Unit Tests for MFS Feature Extractor.
"""

import numpy as np
from mfs_checker.ml.feature_extractor import MFSFeatureExtractor
from tests.mock_apk_builder import build_compliant_mock, build_vulnerable_mock

def test_feature_extractor_dimensions():
    extractor = MFSFeatureExtractor()
    feature_names = extractor.get_feature_names()

    # 45 total features
    assert len(feature_names) == 45
    assert "perm_internet" in feature_names
    assert "api_cipher" in feature_names
    assert "api_root_detection" in feature_names
    assert "api_screen_protection" in feature_names
    assert "api_biometric_prompt" in feature_names
    assert "mf_allow_backup" in feature_names
    assert "code_obfuscation_ratio" in feature_names

def test_feature_vector_extraction():
    extractor = MFSFeatureExtractor()
    apk_c, dex_c, analysis_c = build_compliant_mock()
    vec_c, dict_c = extractor.extract_from_objects(apk_c, dex_c, analysis_c)

    assert isinstance(vec_c, np.ndarray)
    assert vec_c.shape == (45,)
    assert not np.isnan(vec_c).any()
    assert dict_c["perm_internet"] == 1.0
    assert dict_c["mf_allow_backup"] == 0.0

    apk_v, dex_v, analysis_v = build_vulnerable_mock()
    vec_v, dict_v = extractor.extract_from_objects(apk_v, dex_v, analysis_v)
    assert vec_v.shape == (45,)
    assert dict_v["mf_allow_backup"] == 1.0
    assert dict_v["perm_send_sms"] == 1.0
