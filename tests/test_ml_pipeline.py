"""
Unit Tests for Machine Learning Pipeline (LOOCV, Regressors, Anomaly Detectors).
"""

import numpy as np
import pandas as pd
from mfs_checker.ml.dataset import MFSDatasetBuilder
from mfs_checker.ml.classifiers import ComplianceClassifier
from mfs_checker.ml.risk_scorer import MaturityScoreRegressor
from mfs_checker.ml.anomaly_detector import FintechAnomalyDetector
from mfs_checker.ml.explainability import ModelExplainer
from mfs_checker.models import ComplianceTier

def test_dataset_builder():
    builder = MFSDatasetBuilder()
    X, y_comp, y_score = builder.generate_synthetic_fintech_dataset(n_compliant=15, n_non_compliant=15)

    assert X.shape == (30, 45)
    assert len(y_comp) == 30
    assert len(y_score) == 30
    assert set(y_comp.unique()) == {0, 1}
    assert (y_score >= 0).all() and (y_score <= 100).all()

def test_compliance_classifier_loocv():
    builder = MFSDatasetBuilder()
    X, y_comp, _ = builder.generate_synthetic_fintech_dataset(n_compliant=12, n_non_compliant=12)

    clf = ComplianceClassifier(model_type="rf", random_state=42)
    metrics = clf.evaluate_loocv(X, y_comp)

    assert metrics["sample_size"] == 24
    assert metrics["accuracy"] >= 0.85
    assert metrics["f1"] >= 0.85

    # Test Fit and Predict
    clf.fit(X, y_comp)
    sample_vec = X.iloc[0].values
    pred, prob = clf.predict(sample_vec)
    assert pred in [0, 1]
    assert 0.0 <= prob <= 1.0

    # Test feature importances
    top_feat = clf.get_feature_importances(top_n=5)
    assert len(top_feat) == 5
    assert all(isinstance(f[0], str) and isinstance(f[1], float) for f in top_feat)

def test_maturity_score_regressor():
    builder = MFSDatasetBuilder()
    X, _, y_score = builder.generate_synthetic_fintech_dataset(n_compliant=12, n_non_compliant=12)

    reg = MaturityScoreRegressor(model_type="ridge", alpha=1.0)
    metrics = reg.evaluate_loocv(X, y_score)

    assert metrics["sample_size"] == 24
    assert metrics["r2"] >= 0.70
    assert metrics["rmse"] < 25.0

    reg.fit(X, y_score)
    sample_vec = X.iloc[0].values
    score, tier = reg.predict_score(sample_vec)
    assert 0.0 <= score <= 100.0
    assert isinstance(tier, ComplianceTier)

def test_anomaly_detector():
    builder = MFSDatasetBuilder()
    X, y_comp, _ = builder.generate_synthetic_fintech_dataset(n_compliant=20, n_non_compliant=20)

    # Train on compliant baseline
    detector = FintechAnomalyDetector(contamination=0.1)
    detector.fit(X[y_comp == 1])

    # Compliant app should usually be normal
    comp_sample = X[y_comp == 1].iloc[0].values
    is_anom, score, msg = detector.detect_anomaly(comp_sample)
    assert 0.0 <= score <= 1.0
    assert isinstance(is_anom, (bool, np.bool_))

    # Construct extreme outlier vector
    outlier_vec = np.zeros(45, dtype=np.float32)
    outlier_vec[6:15] = 1.0  # Excessive dangerous permissions
    outlier_vec[25] = 1.0   # Cleartext traffic
    is_anom_out, score_out, msg_out = detector.detect_anomaly(outlier_vec)
    assert 0.0 <= score_out <= 1.0

def test_model_explainer():
    explainer = ModelExplainer()
    feature_names = [f"feat_{i}" for i in range(5)]
    feature_vector = np.array([1.0, 0.0, 3.5, 0.0, 1.2])
    importances = [(f"feat_{i}", 0.2) for i in range(5)]

    exps = explainer.explain_prediction(feature_names, feature_vector, importances, top_k=3)
    assert len(exps) == 3
    assert "feature" in exps[0]
    assert "importance_weight" in exps[0]
