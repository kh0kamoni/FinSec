"""
Unsupervised Anomaly Detection for Outlier / Rogue / Trojanized Fintech Apps.
"""

from typing import Tuple, Dict, Any, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class FintechAnomalyDetector:
    """Detects anomalous, repackaged, or rogue fintech apps using unsupervised Isolation Forest."""

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state
        )
        self.is_fitted = False

    def fit(self, X: pd.DataFrame):
        """Fit Isolation Forest on baseline fintech application feature matrix."""
        X_mat = X.values if isinstance(X, pd.DataFrame) else X
        X_scaled = self.scaler.fit_transform(X_mat)
        self.model.fit(X_scaled)
        self.is_fitted = True

    def detect_anomaly(self, feature_vector: np.ndarray) -> Tuple[bool, float, str]:
        """
        Evaluate single feature vector.
        Returns:
            is_anomaly (bool): True if flagged as an anomalous outlier
            anomaly_score (float): Continuous score in [0, 1] where > 0.6 is anomalous
            message (str): Human-readable regulatory assessment
        """
        if not self.is_fitted:
            raise RuntimeError("Anomaly detector must be fitted on baseline data first.")

        feat_2d = feature_vector.reshape(1, -1)
        feat_scaled = self.scaler.transform(feat_2d)

        # score_samples returns negative anomaly score (lower is more anomalous)
        raw_score = float(self.model.score_samples(feat_scaled)[0])
        # Map raw_score (typically in [-0.8, -0.3]) to a 0.0 - 1.0 risk index
        norm_score = max(0.0, min(1.0, 0.5 - (raw_score + 0.5) * 1.5))

        is_outlier = (self.model.predict(feat_scaled)[0] == -1)

        if is_outlier:
            msg = f"FLAGGED: Application exhibits an anomalous security profile (Risk Index: {norm_score:.2f}). Possible rogue clone or uncharacteristic permissions."
        else:
            msg = f"NORMAL: Application features align with expected baseline fintech characteristics (Risk Index: {norm_score:.2f})."

        return is_outlier, norm_score, msg
