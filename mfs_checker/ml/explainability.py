"""
Feature Attribution and Interpretability for Bangladesh Bank Compliance Predictions.
"""

from typing import List, Dict, Tuple, Any
import numpy as np
import pandas as pd

class ModelExplainer:
    """Provides human-readable explanations of ML model predictions for regulatory audits."""

    @staticmethod
    def explain_prediction(
        feature_names: List[str],
        feature_vector: np.ndarray,
        feature_importances: List[Tuple[str, float]],
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Explain the main drivers behind a compliance prediction.
        """
        feat_dict = dict(zip(feature_names, feature_vector))
        explanations = []

        for name, imp in feature_importances[:top_k]:
            val = feat_dict.get(name, 0.0)
            explanations.append({
                "feature": name,
                "importance_weight": round(imp, 4),
                "observed_value": round(float(val), 2),
                "impact": "High Security Risk" if ("weak" in name or "plain" in name or "debug" in name) and val > 0 else "Protective Signal"
            })

        return explanations
