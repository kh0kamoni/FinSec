"""
Leave-One-Out Cross-Validation (LOOCV) & Supervised Compliance Classifiers.
"""

from typing import Dict, Any, Tuple, Optional, List
import numpy as np
import pandas as pd
from sklearn.model_selection import LeaveOneOut, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

class ComplianceClassifier:
    """Supervised classifier trained to predict overall BB compliance or individual rule violations."""

    def __init__(self, model_type: str = "rf", random_state: int = 42):
        self.model_type = model_type
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.is_fitted = False

        if model_type == "rf":
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=5,
                min_samples_split=3,
                random_state=random_state
            )
        elif model_type == "lr":
            self.model = LogisticRegression(
                penalty="l2",
                C=1.0,
                max_iter=1000,
                random_state=random_state
            )
        else:
            raise ValueError(f"Unsupported model type: {model_type}")

    def evaluate_loocv(self, X: pd.DataFrame, y: pd.Series) -> Dict[str, float]:
        """
        Evaluate performance using Leave-One-Out Cross-Validation (ideal for small N ~ 15-50).
        """
        loo = LeaveOneOut()
        y_true = []
        y_pred = []
        y_probs = []

        X_mat = X.values if isinstance(X, pd.DataFrame) else X
        y_vec = y.values if isinstance(y, pd.Series) else y

        for train_idx, test_idx in loo.split(X_mat):
            X_train, X_test = X_mat[train_idx], X_mat[test_idx]
            y_train, y_test = y_vec[train_idx], y_vec[test_idx]

            # Fit scaler strictly on training fold to prevent data leakage
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)

            clf = RandomForestClassifier(n_estimators=50, max_depth=4, random_state=self.random_state) if self.model_type == "rf" else LogisticRegression(max_iter=1000, random_state=self.random_state)
            clf.fit(X_train_scaled, y_train)

            pred = clf.predict(X_test_scaled)[0]
            prob = clf.predict_proba(X_test_scaled)[0][1] if hasattr(clf, "predict_proba") else float(pred)

            y_true.append(y_test[0])
            y_pred.append(pred)
            y_probs.append(prob)

        metrics = {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_true, y_probs)) if len(set(y_true)) > 1 else 1.0,
            "sample_size": len(y_true)
        }
        return metrics

    def fit(self, X: pd.DataFrame, y: pd.Series):
        """Fit model on complete dataset."""
        self.feature_names = list(X.columns) if isinstance(X, pd.DataFrame) else [f"feat_{i}" for i in range(X.shape[1])]
        X_mat = X.values if isinstance(X, pd.DataFrame) else X
        y_vec = y.values if isinstance(y, pd.Series) else y
        X_scaled = self.scaler.fit_transform(X_mat)
        self.model.fit(X_scaled, y_vec)
        self.is_fitted = True

    def predict(self, feature_vector: np.ndarray) -> Tuple[int, float]:
        """Predict compliance (1=Compliant, 0=Non-Compliant) and confidence probability."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before calling predict.")
        feat_2d = feature_vector.reshape(1, -1)
        feat_scaled = self.scaler.transform(feat_2d)
        pred = int(self.model.predict(feat_scaled)[0])
        prob = float(self.model.predict_proba(feat_scaled)[0][1])
        return pred, prob

    def get_feature_importances(self, top_n: int = 10) -> List[Tuple[str, float]]:
        """Return top N most predictive features for Bangladesh Bank compliance."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before extracting importances.")
        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
        elif hasattr(self.model, "coef_"):
            importances = np.abs(self.model.coef_[0])
        else:
            return []

        ranked = sorted(zip(self.feature_names, importances), key=lambda x: x[1], reverse=True)
        return [(name, float(score)) for name, score in ranked[:top_n]]
