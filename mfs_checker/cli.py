"""
Command-Line Interface (CLI) for Bangladesh Bank MFS Compliance Checker.
"""

import argparse
import sys
import os
import glob
from rich.console import Console
from rich.table import Table

from mfs_checker import __version__, __framework__
from mfs_checker.engine import ComplianceEngine
from mfs_checker.reporting import render_console_report, generate_json_report, generate_markdown_report
from mfs_checker.ml import MFSFeatureExtractor, MFSDatasetBuilder, ComplianceClassifier, MaturityScoreRegressor, FintechAnomalyDetector

console = Console()

def cmd_scan(args):
    """Scan a single APK and display / save audit results."""
    apk_path = args.apk_path
    if not os.path.exists(apk_path):
        console.print(f"[bold red]Error: File not found:[/bold red] {apk_path}")
        sys.exit(1)

    console.print(f"[bold cyan]Initiating Bangladesh Bank Compliance Audit on:[/bold cyan] {apk_path}")
    engine = ComplianceEngine()
    scorecard = engine.audit_apk(apk_path)

    # ML Feature Extraction & Assessment
    try:
        extractor = MFSFeatureExtractor()
        feat_vec, feat_dict = extractor.extract_from_apk(apk_path)

        # Train reference models on synthetic baseline for inference
        builder = MFSDatasetBuilder(extractor)
        X, y_comp, y_score = builder.generate_synthetic_fintech_dataset()

        clf = ComplianceClassifier(model_type="rf")
        clf.fit(X, y_comp)
        pred_comp, prob_comp = clf.predict(feat_vec)

        anom_detector = FintechAnomalyDetector()
        anom_detector.fit(X[y_comp == 1])
        is_anom, anom_score, anom_msg = anom_detector.detect_anomaly(feat_vec)

        scorecard.ml_risk_prediction = {
            "predicted_compliant": bool(pred_comp == 1),
            "compliance_probability": prob_comp,
            "anomaly_status": "ANOMALY" if is_anom else "NORMAL",
            "anomaly_risk_index": anom_score,
            "message": anom_msg
        }
    except Exception as e:
        console.print(f"[yellow]Note: ML inference bypassed: {str(e)}[/yellow]")

    # Render console view
    render_console_report(scorecard)

    # Save outputs if specified
    if args.json:
        generate_json_report(scorecard, args.json)
        console.print(f"[green]Saved JSON report to:[/green] {args.json}")

    if args.markdown:
        generate_markdown_report(scorecard, args.markdown)
        console.print(f"[green]Saved Markdown audit report to:[/green] {args.markdown}")

def cmd_batch(args):
    """Scan all APK files in a directory and print comparison scorecard."""
    apk_dir = args.dir_path
    if not os.path.isdir(apk_dir):
        console.print(f"[bold red]Error: Directory not found:[/bold red] {apk_dir}")
        sys.exit(1)

    apk_files = sorted(glob.glob(os.path.join(apk_dir, "*.apk")) + glob.glob(os.path.join(apk_dir, "*.apks")))
    if not apk_files:
        console.print(f"[bold yellow]No APK/APKS files found in directory:[/bold yellow] {apk_dir}")
        return

    console.print(f"[bold cyan]Running batch audit on {len(apk_files)} real MFS applications...[/bold cyan]")
    engine = ComplianceEngine()
    extractor = MFSFeatureExtractor()
    scorecards = []
    feature_rows = []
    summary_rows = []

    os.makedirs("results", exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    for path in apk_files:
        fname = os.path.basename(path)
        console.print(f"Auditing [bold]{fname}[/bold]...")
        try:
            sc = engine.audit_apk(path)
            scorecards.append(sc)

            # Generate individual reports
            base_name = os.path.splitext(fname)[0]
            generate_json_report(sc, f"reports/{base_name}.json")
            generate_markdown_report(sc, f"reports/{base_name}.md")

            # Extract real 42-D feature vector
            vec, feat_dict = extractor.extract_from_apk(path)
            feat_dict["app_name"] = sc.app_name
            feat_dict["package_name"] = sc.package_name
            feat_dict["version"] = sc.version_name
            feat_dict["maturity_score"] = sc.maturity_score
            feat_dict["tier"] = sc.tier.value
            feat_dict["critical_violations"] = sc.critical_violations
            feat_dict["is_compliant"] = 1 if (sc.tier.value.startswith("Tier 1") or (sc.maturity_score >= 80 and sc.critical_violations == 0)) else 0
            feature_rows.append(feat_dict)

            # Summary row for table
            s_row = {
                "File": fname,
                "App Name": sc.app_name,
                "Package": sc.package_name,
                "Version": sc.version_name,
                "Size (MB)": round(sc.apk_size_mb, 2),
                "Maturity Score": round(sc.maturity_score, 1),
                "Regulatory Tier": sc.tier.value.split(":")[0],
                "Passed": sc.passed_rules,
                "Failed": sc.failed_rules,
                "Warnings": sc.warning_rules,
                "Critical Violations": sc.critical_violations
            }
            # Record individual rule statuses
            for r in sc.rule_results:
                s_row[r.rule_id] = r.status.value
            summary_rows.append(s_row)

        except Exception as e:
            console.print(f"[red]Failed to audit {fname}: {str(e)}[/red]")

    # Save empirical summary datasets to CSV and JSON
    if summary_rows:
        import pandas as pd
        df_summary = pd.DataFrame(summary_rows)
        df_summary.to_csv("results/mfs_audit_summary.csv", index=False)
        df_features = pd.DataFrame(feature_rows)
        df_features.to_csv("results/mfs_features_real.csv", index=False)
        console.print("[green]Saved empirical results to results/mfs_audit_summary.csv and results/mfs_features_real.csv[/green]")

    # Print Batch Table
    table = Table(title="Bangladesh Bank MFS Ecosystem Empirical Compliance Audit", header_style="bold magenta")
    table.add_column("App Name", style="bold")
    table.add_column("Package", style="dim")
    table.add_column("Score (0-100)", justify="right")
    table.add_column("Regulatory Tier")
    table.add_column("Pass / Fail / Warn")
    table.add_column("Critical Violations", justify="center")

    for sc in scorecards:
        color = "green" if sc.maturity_score >= 85 else ("yellow" if sc.maturity_score >= 70 else "red")
        table.add_row(
            sc.app_name,
            sc.package_name,
            f"[{color}]{sc.maturity_score:.1f}[/{color}]",
            sc.tier.value.split(":")[0],
            f"{sc.passed_rules} / {sc.failed_rules} / {sc.warning_rules}",
            f"[red]{sc.critical_violations}[/red]" if sc.critical_violations > 0 else "[green]0[/green]"
        )

    console.print(table)

def cmd_train_eval(args):
    """Run full ML training and Leave-One-Out Cross-Validation on fintech dataset."""
    console.print("[bold cyan]Generating realistic fintech dataset and running LOOCV evaluation...[/bold cyan]")
    builder = MFSDatasetBuilder()
    X, y_comp, y_score = builder.generate_synthetic_fintech_dataset(
        n_compliant=args.samples // 2,
        n_non_compliant=args.samples // 2
    )

    console.print(f"Dataset generated: [bold]{X.shape[0]} samples[/bold], [bold]{X.shape[1]} features[/bold]")

    # 1. Classification Evaluation (LOOCV)
    clf_rf = ComplianceClassifier(model_type="rf")
    metrics_rf = clf_rf.evaluate_loocv(X, y_comp)

    clf_lr = ComplianceClassifier(model_type="lr")
    metrics_lr = clf_lr.evaluate_loocv(X, y_comp)

    console.print("\n[bold]LOOCV Classification Results (Compliance Prediction):[/bold]")
    table_clf = Table(header_style="bold blue")
    table_clf.add_column("Model")
    table_clf.add_column("Accuracy")
    table_clf.add_column("Precision")
    table_clf.add_column("Recall")
    table_clf.add_column("F1-Score")
    table_clf.add_column("ROC-AUC")

    for name, m in [("Random Forest", metrics_rf), ("Logistic Regression", metrics_lr)]:
        table_clf.add_row(
            name,
            f"{m['accuracy']:.3f}",
            f"{m['precision']:.3f}",
            f"{m['recall']:.3f}",
            f"{m['f1']:.3f}",
            f"{m['roc_auc']:.3f}"
        )
    console.print(table_clf)

    # 2. Regression Evaluation (Maturity Score Prediction)
    reg_ridge = MaturityScoreRegressor(model_type="ridge")
    metrics_reg = reg_ridge.evaluate_loocv(X, y_score)

    console.print("\n[bold]LOOCV Regression Results (Maturity Score 0-100):[/bold]")
    console.print(f"Ridge Regressor -> RMSE: [bold]{metrics_reg['rmse']:.2f}[/bold], MAE: [bold]{metrics_reg['mae']:.2f}[/bold], R²: [bold]{metrics_reg['r2']:.3f}[/bold]")

    # 3. Top Feature Importances
    clf_rf.fit(X, y_comp)
    top_features = clf_rf.get_feature_importances(top_n=10)

    console.print("\n[bold]Top 10 Most Predictive Features for Bangladesh Bank Compliance:[/bold]")
    table_feat = Table(header_style="bold green")
    table_feat.add_column("Rank", justify="center")
    table_feat.add_column("Feature Identifier")
    table_feat.add_column("Importance Weight", justify="right")

    for idx, (fname, weight) in enumerate(top_features, 1):
        table_feat.add_row(str(idx), fname, f"{weight:.4f}")
    console.print(table_feat)

def main():
    parser = argparse.ArgumentParser(
        description=f"Bangladesh Bank MFS Cybersecurity Compliance Checker ({__framework__})"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Scan command
    p_scan = subparsers.add_parser("scan", help="Audit a single Android APK")
    p_scan.add_argument("apk_path", help="Path to APK file")
    p_scan.add_argument("--json", help="Export audit results to JSON file path")
    p_scan.add_argument("--markdown", help="Export audit results to Markdown file path")
    p_scan.set_defaults(func=cmd_scan)

    # Batch scan command
    p_batch = subparsers.add_parser("batch", help="Batch audit multiple APKs in a directory")
    p_batch.add_argument("dir_path", help="Directory containing APK files")
    p_batch.set_defaults(func=cmd_batch)

    # Train and evaluate command
    p_train = subparsers.add_parser("train-eval", help="Run ML Leave-One-Out Cross-Validation")
    p_train.add_argument("--samples", type=int, default=50, help="Number of samples (default: 50)")
    p_train.set_defaults(func=cmd_train_eval)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
