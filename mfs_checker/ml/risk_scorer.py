"""
Continuous Bangladesh Bank Cybersecurity Maturity Score Regressor (0-100 Index).
"""

from typing import Dict, Any, Tuple, Optional
import numpy as np
import pandas as pd
from sklearn.model_selection import LeaveOneOut
from sklearn.linear_model import Ridge
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
from mfs_checker.models import ComplianceTier

class MaturityScoreRegressor:
    """Predicts continuous 0-100 security maturity score from static APK features."""

    def __init__(self, model_type: str = "ridge", alpha: float = 1.0, random_state: int = 42):
        self.model_type = model_type
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.is_fitted = False

        if model_type == "ridge":
            self.model = Ridge(alpha=alpha, random_state=random_state)
        elif model_type == "rf":
            self.model = RandomForestRegressor(n_estimators=100, max_depth=5, random_state=random_state)
        else:
            raise ValueError(f"Unsupported regressor: {model_type}")

    def evaluate_loocv(self, X: pd.DataFrame, y: pd.Series) -> Dict[str, float]:
        loo = LeaveOneOut()
        y_true = []
        y_pred = []

        X_mat = X.values if isinstance(X, pd.DataFrame) else X
        y_vec = y.values if isinstance(y, pd.Series) else y

        for train_idx, test_idx in loo.split(X_mat):
            X_train, X_test = X_mat[train_idx], X_mat[test_idx]
            y_train, y_test = y_vec[train_idx], y_vec[test_idx]

            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)

            reg = Ridge(alpha=1.0) if self.model_type == "ridge" else RandomForestRegressor(n_estimators=50, max_depth=4, random_state=self.random_state)
            reg.fit(X_train_scaled, y_train)

            pred = reg.predict(X_test_scaled)[0]
            # Clip between 0 and 100
            pred = max(0.0, min(100.0, float(pred)))

            y_true.append(float(y_test[0]))
            y_pred.append(pred)

        mse = mean_squared_error(y_true, y_pred)
        rmse = float(np.sqrt(mse))
        mae = float(mean_absolute_error(y_true, y_pred))
        r2 = float(r2_score(y_true, y_pred))

        return {
            "rmse": rmse,
            "mae": mae,
            "r2": r2,
            "sample_size": len(y_true)
        }

    def fit(self, X: pd.DataFrame, y: pd.Series):
        X_mat = X.values if isinstance(X, pd.DataFrame) else X
        y_vec = y.values if isinstance(y, pd.Series) else y
        X_scaled = self.scaler.fit_transform(X_mat)
        self.model.fit(X_scaled, y_vec)
        self.is_fitted = True

    def predict_score(self, feature_vector: np.ndarray) -> Tuple[float, ComplianceTier]:
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predicting.")
        feat_2d = feature_vector.reshape(1, -1)
        feat_scaled = self.scaler.transform(feat_2d)
        score = float(self.model.predict(feat_scaled)[0])
        score = max(0.0, min(100.0, round(score, 1)))

        if score >= 85.0:
            tier = ComplianceTier.TIER_1_COMPLIANT
        elif score >= 70.0:
            tier = ComplianceTier.TIER_2_CONDITIONAL
        else:
            tier = ComplianceTier.TIER_3_HIGH_RISK

        return score, tier
