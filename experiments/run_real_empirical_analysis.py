"""
Empirical Evaluation Script for Real Bangladesh MFS Dataset.
Executes LOOCV Ridge Regression, Isolation Forest Anomaly Detection,
Feature Importance Ranking, and generates publication charts for NSysS 2026.
"""

import os
import sys
sys.path.insert(0, os.path.abspath("."))
import numpy as np
import pandas as pd
from sklearn.linear_model import Ridge
from sklearn.ensemble import RandomForestRegressor, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
from mfs_checker.ml.feature_extractor import MFSFeatureExtractor
from mfs_checker.reporting.visualizer import MFSVisualizer

def main():
    print("=== Processing Real Empirical MFS Dataset ===")
    df_sum = pd.read_csv("results/mfs_audit_summary.csv")
    df_feat = pd.read_csv("results/mfs_features_real.csv")

    extractor = MFSFeatureExtractor()
    feature_names = extractor.feature_names

    X = df_feat[feature_names].values
    y_score = df_feat["maturity_score"].values
    app_names = df_feat["app_name"].values

    N = len(df_feat)
    print(f"Total Evaluated Real Binaries: {N}")

    # 1. Leave-One-Out Cross-Validation (LOOCV) for Continuous Maturity Score
    y_pred_loocv = np.zeros(N)
    for i in range(N):
        train_idx = [j for j in range(N) if j != i]
        test_idx = [i]

        X_train, y_train = X[train_idx], y_score[train_idx]
        X_test = X[test_idx]

        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Regularized Ridge Regressor (alpha=1.0)
        reg = Ridge(alpha=1.0)
        reg.fit(X_train_scaled, y_train)
        y_pred_loocv[i] = reg.predict(X_test_scaled)[0]

    r2 = r2_score(y_score, y_pred_loocv)
    rmse = np.sqrt(mean_squared_error(y_score, y_pred_loocv))
    mae = mean_absolute_error(y_score, y_pred_loocv)

    print(f"\n--- LOOCV Regression Results (Ridge on 12 Real Apps) ---")
    print(f"R² Score: {r2:.4f}")
    print(f"RMSE:     {rmse:.2f}")
    print(f"MAE:      {mae:.2f}")

    for name, true_s, pred_s in zip(app_names, y_score, y_pred_loocv):
        print(f"  {name:15s} | True: {true_s:4.1f} | Pred: {pred_s:4.1f} | Diff: {abs(true_s - pred_s):4.1f}")

    # 2. Feature Importance via Random Forest Regressor
    rf = RandomForestRegressor(n_estimators=100, max_depth=4, random_state=42)
    scaler_all = StandardScaler()
    X_scaled = scaler_all.fit_transform(X)
    rf.fit(X_scaled, y_score)

    importances = rf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [(feature_names[idx], float(importances[idx])) for idx in sorted_idx[:10]]

    print(f"\n--- Top 10 Most Predictive Features on Real Apps ---")
    for rank, (fname, imp) in enumerate(top_features, 1):
        print(f"  {rank:2d}. {fname:30s}: {imp:.4f}")

    # 3. Unsupervised Isolation Forest Anomaly Detection
    iso = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    iso.fit(X_scaled)
    raw_scores = iso.score_samples(X_scaled)
    # Normalize to 0.0 - 1.0 risk index
    anomaly_indices = [max(0.0, min(1.0, 0.5 - (s + 0.5) * 1.5)) for s in raw_scores]
    is_outliers = iso.predict(X_scaled) == -1

    print(f"\n--- Unsupervised Anomaly Risk Index ---")
    df_sum["Anomaly Risk"] = np.round(anomaly_indices, 3)
    df_sum["Is Outlier"] = is_outliers
    for name, s, a_idx, out in zip(app_names, y_score, anomaly_indices, is_outliers):
        status = "OUTLIER" if out else "Normal"
        print(f"  {name:15s} | Score: {s:4.1f} | Anomaly Risk: {a_idx:.3f} | {status}")

    df_sum.to_csv("results/mfs_audit_summary.csv", index=False)

    # 4. Generate Publication Figures
    viz = MFSVisualizer(output_dir="paper/figures")

    # A. Clause Violation Rates
    rules_map = {
        "BB-MFS-01": "BB-MFS-01: Data at Rest (Plaintext DB/Prefs)",
        "BB-MFS-02": "BB-MFS-02: SAD/CHD Logging (PIN/OTP)",
        "BB-MFS-03": "BB-MFS-03: Transport Security (TLS/Pinning)",
        "BB-MFS-04": "BB-MFS-04: Crypto Strength (Insecure Ciphers)",
        "BB-MFS-05": "BB-MFS-05: Hardware KeyStore Isolation",
        "BB-MFS-06": "BB-MFS-06: Transaction Signing / HMAC",
        "BB-MFS-07": "BB-MFS-07: Secure Random PRNG",
        "BB-MFS-08": "BB-MFS-08: Least Privilege Permissions",
        "BB-MFS-09": "BB-MFS-09: Manifest Hardening (Backup/Debug)",
        "BB-MFS-10": "BB-MFS-10: Source Code Obfuscation",
        "BB-MFS-11": "BB-MFS-11: Hardcoded Secrets & Cloud Keys",
        "BB-MFS-12": "BB-MFS-12: Root & Environment Integrity Check",
        "BB-MFS-13": "BB-MFS-13: Screen Capture / Overlay Shielding",
        "BB-MFS-14": "BB-MFS-14: Biometric Crypto Binding"
    }
    clause_stats = {}
    for r_code, r_label in rules_map.items():
        fails = sum(df_sum[r_code] == "FAILED")
        clause_stats[r_label] = fails / N

    viz.plot_clause_violation_rates(clause_stats, filename="clause_violations.pdf")

    # B. Maturity Score Distribution
    viz.plot_maturity_score_distribution(y_score.tolist(), filename="maturity_distribution.pdf")

    # C. Feature Importance Chart
    viz.plot_feature_importance_radar_or_bar(top_features, filename="feature_importance.pdf")

    # D. Anomaly Scatter
    categories = []
    for s in y_score:
        if s >= 55:
            categories.append("Tier 3 (Upper: bKash/Rocket/upay)")
        elif s >= 45:
            categories.append("Tier 3 (Mid: mCash/TeleCash/IW)")
        else:
            categories.append("Tier 3 (Lower: Meghna/Nagad/TAP)")
    
    viz.plot_anomaly_scatter(y_score.tolist(), anomaly_indices, categories, filename="anomaly_scatter.pdf")

    print("\n[SUCCESS] Generated all 4 publication charts in paper/figures/")

if __name__ == "__main__":
    main()
