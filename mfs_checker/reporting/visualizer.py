"""
Visualization and Graph Generation Module for Bangladesh Bank MFS Empirical Audits.
Generates publication-quality figures for inclusion in the NSysS 2026 paper.
"""

import os
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional

# Set publication style (clean, academic font sizes, crisp DPI)
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 9,
    'axes.labelsize': 10,
    'axes.titlesize': 11,
    'xtick.labelsize': 8.5,
    'ytick.labelsize': 8.5,
    'legend.fontsize': 8.5,
    'figure.titlesize': 12,
    'figure.dpi': 300
})

class MFSVisualizer:
    """Generates charts for empirical MFS compliance papers."""

    def __init__(self, output_dir: str = "paper/figures"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def plot_clause_violation_rates(self, clause_stats: Dict[str, float], filename: str = "clause_violations.pdf"):
        """
        Plot horizontal bar chart of violation rates across the 11 BB clauses.
        clause_stats: dict of {"BB-MFS-01 (Data at Rest)": 0.65, ...}
        """
        plt.figure(figsize=(7.0, 3.8))
        sorted_items = sorted(clause_stats.items(), key=lambda x: x[1], reverse=True)
        labels = [item[0] for item in sorted_items]
        rates = [item[1] * 100 for item in sorted_items]

        colors = ['#d9534f' if r >= 50 else ('#f0ad4e' if r >= 25 else '#5cb85c') for r in rates]

        y_pos = np.arange(len(labels))
        bars = plt.barh(y_pos, rates, color=colors, edgecolor='black', linewidth=0.6, height=0.65)
        plt.yticks(y_pos, labels)
        plt.xlabel("Violation Rate (% of Evaluated MFS Binaries)")
        plt.xlim(0, 100)
        plt.gca().invert_yaxis()  # Top to bottom

        # Add data value labels
        for bar, r in zip(bars, rates):
            plt.text(bar.get_width() + 1.2, bar.get_y() + bar.get_height() / 2,
                     f"{r:.1f}%", va='center', ha='left', fontsize=8, fontweight='bold')

        plt.title("Prevalence of Technical Clause Violations across Evaluated Bangladeshi MFS Binaries", pad=12)
        plt.tight_layout()
        out_path = os.path.join(self.output_dir, filename)
        plt.savefig(out_path, format="pdf", bbox_inches="tight")
        plt.savefig(out_path.replace(".pdf", ".png"), format="png", dpi=300, bbox_inches="tight")
        plt.close()
        return out_path

    def plot_maturity_score_distribution(self, scores: List[float], filename: str = "maturity_distribution.pdf"):
        """
        Plot distribution of Cybersecurity Maturity Scores across Tier 1, 2, and 3 thresholds.
        """
        plt.figure(figsize=(6.5, 3.4))
        sns.histplot(scores, bins=12, kde=True, color='#337ab7', edgecolor='black', alpha=0.6)

        # Threshold lines
        plt.axvline(85, color='#5cb85c', linestyle='--', linewidth=1.5, label='Tier 1 Baseline (Score ≥ 85)')
        plt.axvline(70, color='#d9534f', linestyle='--', linewidth=1.5, label='Tier 3 Threshold (Score < 70)')

        plt.xlabel("Bangladesh Bank Cybersecurity Maturity Score (0–100)")
        plt.ylabel("Number of Applications")
        plt.title("Ecosystem Maturity Score Distribution & Regulatory Tier Boundaries", pad=10)
        plt.legend(loc='upper left', frameon=True)
        plt.xlim(0, 100)
        plt.tight_layout()
        out_path = os.path.join(self.output_dir, filename)
        plt.savefig(out_path, format="pdf", bbox_inches="tight")
        plt.savefig(out_path.replace(".pdf", ".png"), format="png", dpi=300, bbox_inches="tight")
        plt.close()
        return out_path

    def plot_feature_importance_radar_or_bar(self, feature_ranks: List[tuple], filename: str = "feature_importance.pdf"):
        """
        Plot horizontal bar chart of top predictive Gini importance weights.
        feature_ranks: list of (feature_name, weight)
        """
        plt.figure(figsize=(6.8, 3.6))
        features = [f[0].replace("api_", "").replace("perm_", "p_").replace("code_", "").replace("mf_", "") for f in feature_ranks[:10]]
        weights = [f[1] for f in feature_ranks[:10]]

        y_pos = np.arange(len(features))
        bars = plt.barh(y_pos, weights, color='#2c3e50', edgecolor='black', linewidth=0.6, height=0.6)
        plt.yticks(y_pos, features)
        plt.xlabel("Gini Impurity Feature Importance Weight")
        plt.gca().invert_yaxis()

        for bar, w in zip(bars, weights):
            plt.text(bar.get_width() + 0.002, bar.get_y() + bar.get_height() / 2,
                     f"{w:.4f}", va='center', ha='left', fontsize=8)

        plt.xlim(0, max(weights) * 1.25)
        plt.title("Top 10 Most Predictive Static Features for Central Bank Compliance", pad=10)
        plt.tight_layout()
        out_path = os.path.join(self.output_dir, filename)
        plt.savefig(out_path, format="pdf", bbox_inches="tight")
        plt.savefig(out_path.replace(".pdf", ".png"), format="png", dpi=300, bbox_inches="tight")
        plt.close()
        return out_path

    def plot_anomaly_scatter(self, scores: List[float], anomaly_indices: List[float], labels: List[str], filename: str = "anomaly_scatter.pdf"):
        """
        Scatter plot mapping Cybersecurity Maturity Score against Isolation Forest Anomaly Risk Index.
        """
        plt.figure(figsize=(6.8, 3.8))
        df = pd.DataFrame({
            "MaturityScore": scores,
            "AnomalyRisk": anomaly_indices,
            "Category": labels
        })

        # Scatter
        unique_cats = list(dict.fromkeys(labels))
        default_colors = ['#d9534f', '#f0ad4e', '#337ab7', '#5cb85c', '#9b59b6', '#1abc9c']
        palette = {cat: default_colors[i % len(default_colors)] for i, cat in enumerate(unique_cats)}
        sns.scatterplot(
            data=df, x="MaturityScore", y="AnomalyRisk", hue="Category",
            palette=palette, style="Category", s=90, edgecolor='black', alpha=0.9
        )

        # Anomaly threshold line
        plt.axhline(0.60, color='red', linestyle=':', linewidth=1.2, label='Anomaly Threshold (≥ 0.60)')

        plt.xlabel("Bangladesh Bank Cybersecurity Maturity Score (0–100)")
        plt.ylabel("Unsupervised Anomaly Risk Index (0.00–1.00)")
        plt.title("Correlation: Cybersecurity Maturity vs. Unsupervised Anomaly Risk", pad=10)
        plt.xlim(0, 105)
        plt.ylim(0, 1.05)
        plt.legend(loc='lower left', frameon=True)
        plt.tight_layout()
        out_path = os.path.join(self.output_dir, filename)
        plt.savefig(out_path, format="pdf", bbox_inches="tight")
        plt.savefig(out_path.replace(".pdf", ".png"), format="png", dpi=300, bbox_inches="tight")
        plt.close()
        return out_path
