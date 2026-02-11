import os
import pickle

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score, f1_score,
    precision_score, recall_score, roc_curve, auc
)
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.utils import resample

"""
🚀 ADVANCED Cloud Threat Detection Training Script
-----------------------------------------------------------------
This script trains an optimized RandomForest classifier on BOTH Kaggle datasets:
- CICIDS2017_improved
- CSECICIDS2018_improved

Features:
✓ Dual dataset loading (2x more training data)
✓ Smart feature selection (top 20 features)
✓ Cross-validation (5-fold stratified K-fold)
✓ Class balancing with class_weight
✓ Feature normalization for better predictions
✓ Comprehensive metrics (ROC-AUC, F1, Precision, Recall)
✓ Advanced RandomForest hyperparameters
"""

# =========================
# CONFIGURATION (OPTIMIZED)
# =========================

ML_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FOLDERS = [
    os.path.join(ML_DIR, "CICIDS2017_improved"),
    os.path.join(ML_DIR, "CSECICIDS2018_improved"),
]
CHUNK_SIZE = 50000
SAMPLE_PER_CHUNK = 5000
RANDOM_STATE = 42
TEST_SIZE = 0.2
CV_FOLDS = 5

# ✨ IMPROVED HYPERPARAMETERS
N_ESTIMATORS = 300  # More trees = better accuracy
MAX_DEPTH = 20  # Deeper trees for complex patterns
MIN_SAMPLES_SPLIT = 5  # Allow smaller nodes for fine-grained decisions
MIN_SAMPLES_LEAF = 2  # More sensitive to minority class
MAX_FEATURES = "sqrt"  # Better feature sampling
CLASS_WEIGHT = "balanced_subsample"  # Better imbalance handling

IMBALANCE_STRATEGY = "class_weight"  # Preferred over downsampling (keeps data)

MODEL_PATH = os.path.join(ML_DIR, "rf_model.pkl")
FEATURES_PATH = os.path.join(ML_DIR, "feature_columns.pkl")
SCALER_PATH = os.path.join(ML_DIR, "feature_scaler.pkl")  # NEW: Save scaler
FEATURE_IMPORTANCE_PNG = os.path.join(ML_DIR, "feature_importance_top20.png")
EVAL_REPORT_PATH = os.path.join(ML_DIR, "model_evaluation_report.txt")

def load_and_sample_data(data_folders: list) -> pd.DataFrame:
    """Load all CSV files from BOTH datasets in chunks, clean, and sample rows."""
    all_samples = []

    total_files = 0
    for data_folder in data_folders:
        if not os.path.exists(data_folder):
            print(f"⚠️  Warning: Dataset folder not found: {data_folder}")
            continue
            
        csv_files = [f for f in os.listdir(data_folder) if f.endswith(".csv")]
        total_files += len(csv_files)

    if total_files == 0:
        raise FileNotFoundError(f"No CSV files found in any folder: {data_folders}")

    print(f"🔍 Found {total_files} CSV file(s) across datasets. Starting chunked load...")

    for data_folder in data_folders:
        if not os.path.exists(data_folder):
            continue
            
        csv_files = [f for f in os.listdir(data_folder) if f.endswith(".csv")]
        dataset_name = os.path.basename(data_folder)
        print(f"\n📂 Processing {dataset_name} ({len(csv_files)} files)...")

        for file in csv_files:
            file_path = os.path.join(data_folder, file)
            print(f"  └─ Loading: {file}")

            try:
                for chunk in pd.read_csv(
                    file_path,
                    chunksize=CHUNK_SIZE,
                    encoding="latin1",
                    low_memory=False,
                ):
                    # Clean data: replace inf with NaN, drop NaN
                    chunk = chunk.replace([np.inf, -np.inf], np.nan)
                    chunk = chunk.dropna()

                    if len(chunk) == 0:
                        continue

                    # Randomly sample rows from each chunk
                    sample_size = min(SAMPLE_PER_CHUNK, len(chunk))
                    sample = chunk.sample(sample_size, random_state=RANDOM_STATE)
                    all_samples.append(sample)
            except Exception as e:
                print(f"    ⚠️  Error processing {file}: {e}")
                continue

    if not all_samples:
        raise ValueError("No valid data after cleaning and sampling.")

    combined = pd.concat(all_samples, ignore_index=True)
    print(f"\n✅ Combined dataset shape: {combined.shape}")
    print(f"   Total rows: {len(combined):,}")
    print(f"   Total columns: {len(combined.columns)}")
    return combined

def preprocess_data(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Create binary labels and select numeric features."""
    # Normalize column names
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise KeyError("Required column 'Label' not found in dataset.")

    # Binary label: BENIGN -> 0, others -> 1
    df["binary_label"] = df["Label"].apply(lambda x: 0 if str(x).strip() == "BENIGN" else 1)

    # Select numeric features only (exclude target)
    numeric_features = df.select_dtypes(include=["float64", "int64"]).copy()
    if "binary_label" in numeric_features.columns:
        numeric_features = numeric_features.drop(columns=["binary_label"])

    if numeric_features.empty:
        raise ValueError("No numeric features found after preprocessing.")

    X = numeric_features
    y = df["binary_label"].astype(int)

    print(f"Numeric feature columns: {len(X.columns)}")
    return X, y

def handle_class_imbalance(X: pd.DataFrame, y: pd.Series) -> tuple[pd.DataFrame, pd.Series, dict | None]:
    """Handle class imbalance via downsampling or class_weight."""
    if IMBALANCE_STRATEGY == "downsample":
        print("Handling imbalance with downsampling...")
        df_combined = pd.concat([X, y], axis=1)

        normal = df_combined[df_combined.binary_label == 0]
        attack = df_combined[df_combined.binary_label == 1]

        if len(attack) == 0 or len(normal) == 0:
            raise ValueError("Cannot downsample because one class is empty.")

        # Downsample majority class to match minority class
        normal_downsampled = resample(
            normal,
            replace=False,
            n_samples=len(attack),
            random_state=RANDOM_STATE,
        )

        balanced_df = pd.concat([normal_downsampled, attack])
        X_balanced = balanced_df.drop("binary_label", axis=1)
        y_balanced = balanced_df["binary_label"].astype(int)

        print("Balanced class distribution:")
        print(y_balanced.value_counts())
        return X_balanced, y_balanced, None

    if IMBALANCE_STRATEGY == "class_weight":
        print("Handling imbalance with class_weight='balanced'...")
        return X, y, {"class_weight": "balanced"}

    raise ValueError("IMBALANCE_STRATEGY must be 'downsample' or 'class_weight'.")

def split_data(X: pd.DataFrame, y: pd.Series) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """Split data into train/test sets."""
    print("Splitting data into train/test...")
    return train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )


def train_random_forest(X_train: pd.DataFrame, y_train: pd.Series, class_weight_kwargs: dict | None) -> RandomForestClassifier:
    """Train a RandomForestClassifier."""
    print("Training RandomForest model...")
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        **(class_weight_kwargs or {}),
    )
    model.fit(X_train, y_train)
    print("Training complete!")
    return model


def get_top_features(model: RandomForestClassifier, feature_names: list[str], top_n: int = 20) -> list[str]:
    """Return names of top N features by importance."""
    importances = model.feature_importances_
    indices = np.argsort(importances)[-top_n:][::-1]
    top_features = [feature_names[i] for i in indices]
    top_importances = importances[indices]
    
    print(f"\n🏆 Top {top_n} Features by Importance:")
    for i, (feat, imp) in enumerate(zip(top_features, top_importances), 1):
        print(f"  {i:2d}. {feat:40s} → {imp:.4f}")
    
    return top_features


def evaluate_model(model: RandomForestClassifier, X_test: pd.DataFrame, y_test: pd.Series, model_name: str = "Model") -> dict:
    """Evaluate model with comprehensive metrics."""
    from sklearn.metrics import confusion_matrix

    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]

    print(f"\n{'='*70}")
    print(f"📊 EVALUATION REPORT: {model_name}")
    print(f"{'='*70}")

    # Classification Report
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))

    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(cm)
    tn, fp, fn, tp = cm.ravel()
    print(f"  TN={tn}, FP={fp}, FN={fn}, TP={tp}")

    # Advanced Metrics
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    
    print(f"\n🎯 Advanced Metrics:")
    print(f"  Precision: {precision:.4f} (how many predictions are correct)")
    print(f"  Recall:    {recall:.4f} (how many actual attacks we catch)")
    print(f"  F1-Score:  {f1:.4f} (balance between precision and recall)")
    print(f"  ROC-AUC:   {roc_auc:.4f} (overall model performance)")

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "accuracy": (tp + tn) / (tp + tn + fp + fn)
    }

def cross_validate_model(X_train: pd.DataFrame, y_train: pd.Series, class_weight_kwargs: dict | None) -> None:
    """Perform 5-fold cross-validation for robust accuracy estimation."""
    print(f"\n{'='*70}")
    print(f"🔄 CROSS-VALIDATION (5-Fold Stratified)")
    print(f"{'='*70}")
    
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        min_samples_split=MIN_SAMPLES_SPLIT,
        min_samples_leaf=MIN_SAMPLES_LEAF,
        max_features=MAX_FEATURES,
        class_weight=CLASS_WEIGHT,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    
    # Test multiple metrics
    metrics = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    results = {}
    
    for metric in metrics:
        scores = cross_val_score(model, X_train, y_train, cv=cv, scoring=metric, n_jobs=-1)
        results[metric] = scores
        print(f"\n{metric.upper():10s}:")
        print(f"  Fold scores: {[f'{s:.4f}' for s in scores]}")
        print(f"  Mean:        {scores.mean():.4f} ± {scores.std():.4f}")
    
    return results

def plot_feature_importance(model: RandomForestClassifier, feature_names: list[str]) -> None:
    """Plot and save top 20 feature importances."""
    if not hasattr(model, "feature_importances_"):
        print("Model does not support feature importances.")
        return

    importances = model.feature_importances_
    if len(importances) == 0:
        print("No feature importances found.")
        return

    top_n = min(20, len(importances))
    indices = np.argsort(importances)[-top_n:][::-1]
    top_features = [feature_names[i] for i in indices]
    top_importances = importances[indices]

    plt.figure(figsize=(12, 8))
    plt.barh(top_features[::-1], top_importances[::-1], color="steelblue", edgecolor="navy", alpha=0.8)
    plt.xlabel("Feature Importance Score", fontsize=12, fontweight="bold")
    plt.title("Top 20 Features for Threat Detection", fontsize=14, fontweight="bold")
    plt.grid(axis="x", alpha=0.3)
    plt.tight_layout()
    plt.savefig(FEATURE_IMPORTANCE_PNG, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"✅ Feature importance plot saved: {FEATURE_IMPORTANCE_PNG}")


def main() -> None:
    print("🚀 STARTING ADVANCED ML MODEL TRAINING\n")
    
    # =========================
    # LOAD DATA (BOTH DATASETS)
    # =========================
    print("📥 Phase 1: Loading Data")
    print("="*70)
    df = load_and_sample_data(DATA_FOLDERS)

    # =========================
    # PREPROCESSING
    # =========================
    print("\n📊 Phase 2: Preprocessing")
    print("="*70)
    X, y = preprocess_data(df)

    # =========================
    # HANDLE CLASS IMBALANCE
    # =========================
    print("\n⚖️  Phase 3: Handling Class Imbalance")
    print("="*70)
    X_final, y_final, class_weight_kwargs = handle_class_imbalance(X, y)

    # =========================
    # CROSS-VALIDATION (Robust Accuracy Estimate)
    # =========================
    print("\n🔄 Phase 4: Cross-Validation")
    print("="*70)
    cv_results = cross_validate_model(X_final, y_final, class_weight_kwargs)

    # =========================
    # TRAIN/TEST SPLIT
    # =========================
    print("\n🔀 Phase 5: Train/Test Split")
    print("="*70)
    X_train, X_test, y_train, y_test = split_data(X_final, y_final)
    print(f"Training set: {len(X_train):,} samples")
    print(f"Test set:     {len(X_test):,} samples")

    # =========================
    # FEATURE SCALING (NEW)
    # =========================
    print("\n📏 Phase 6: Feature Normalization")
    print("="*70)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    X_train_scaled = pd.DataFrame(X_train_scaled, columns=X_train.columns)
    X_test_scaled = pd.DataFrame(X_test_scaled, columns=X_test.columns)
    print("✅ Features normalized using StandardScaler")

    # =========================
    # INITIAL TRAIN WITH IMPROVED HYPERPARAMETERS
    # =========================
    print("\n🤖 Phase 7: Training RandomForest (All Features)")
    print("="*70)
    print(f"Hyperparameters:")
    print(f"  n_estimators:      {N_ESTIMATORS}")
    print(f"  max_depth:         {MAX_DEPTH}")
    print(f"  min_samples_split: {MIN_SAMPLES_SPLIT}")
    print(f"  min_samples_leaf:  {MIN_SAMPLES_LEAF}")
    print(f"  max_features:      {MAX_FEATURES}")
    print(f"  class_weight:      {CLASS_WEIGHT}")
    
    initial_model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        min_samples_split=MIN_SAMPLES_SPLIT,
        min_samples_leaf=MIN_SAMPLES_LEAF,
        max_features=MAX_FEATURES,
        class_weight=CLASS_WEIGHT,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    initial_model.fit(X_train_scaled, y_train)
    print("✅ Initial training complete!")

    # =========================
    # SELECT TOP 20 FEATURES
    # =========================
    print("\n🏆 Phase 8: Feature Selection")
    print("="*70)
    top_features = get_top_features(initial_model, X_train.columns.tolist(), top_n=20)

    # =========================
    # RETRAIN WITH TOP 20 FEATURES
    # =========================
    print("\n🎯 Phase 9: Retraining with Top 20 Features")
    print("="*70)
    X_train_top = X_train_scaled[top_features]
    X_test_top = X_test_scaled[top_features]

    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        min_samples_split=MIN_SAMPLES_SPLIT,
        min_samples_leaf=MIN_SAMPLES_LEAF,
        max_features=MAX_FEATURES,
        class_weight=CLASS_WEIGHT,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train_top, y_train)
    print("✅ Retraining complete with optimized features!")

    # =========================
    # EVALUATION ON TEST SET
    # =========================
    print("\n📈 Phase 10: Model Evaluation")
    print("="*70)
    eval_metrics = evaluate_model(model, X_test_top, y_test, "Final Model (Top 20 Features)")

    # =========================
    # FEATURE IMPORTANCE PLOT (TOP 20)
    # =========================
    print("\n📊 Phase 11: Feature Importance Visualization")
    print("="*70)
    plot_feature_importance(model, top_features)

    # =========================
    # SAVE MODEL + FEATURES + SCALER
    # =========================
    print("\n💾 Phase 12: Saving Model Artifacts")
    print("="*70)
    with open(MODEL_PATH, "wb") as model_file:
        pickle.dump(model, model_file)
    print(f"✅ Model saved: {MODEL_PATH}")
    
    with open(FEATURES_PATH, "wb") as features_file:
        pickle.dump(top_features, features_file)
    print(f"✅ Features saved: {FEATURES_PATH}")
    
    with open(SCALER_PATH, "wb") as scaler_file:
        pickle.dump(scaler, scaler_file)
    print(f"✅ Scaler saved: {SCALER_PATH}")

    # =========================
    # SAVE EVALUATION REPORT
    # =========================
    print("\n📝 Phase 13: Saving Evaluation Report")
    print("="*70)
    with open(EVAL_REPORT_PATH, "w") as f:
        f.write("🚀 AEGISCLOUD ML MODEL EVALUATION REPORT\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Training Data: {len(X_train):,} samples\n")
        f.write(f"Test Data:     {len(X_test):,} samples\n")
        f.write(f"Total Features Selected: {len(top_features)}\n\n")
        f.write("TEST SET METRICS:\n")
        f.write(f"  Accuracy:  {eval_metrics['accuracy']:.4f}\n")
        f.write(f"  Precision: {eval_metrics['precision']:.4f}\n")
        f.write(f"  Recall:    {eval_metrics['recall']:.4f}\n")
        f.write(f"  F1-Score:  {eval_metrics['f1']:.4f}\n")
        f.write(f"  ROC-AUC:   {eval_metrics['roc_auc']:.4f}\n\n")
        f.write("CROSS-VALIDATION RESULTS (5-Fold):\n")
        for metric, scores in cv_results.items():
            f.write(f"  {metric.upper():10s}: {scores.mean():.4f} ± {scores.std():.4f}\n")
    print(f"✅ Report saved: {EVAL_REPORT_PATH}")

    print("\n" + "=" * 70)
    print("🎉 MODEL TRAINING COMPLETE!")
    print("=" * 70)
    print(f"\n📌 Summary:")
    print(f"   Datasets: CICIDS2017 + CSECICIDS2018")
    print(f"   Features: {len(top_features)} selected")
    print(f"   Accuracy: {eval_metrics['accuracy']:.2%}")
    print(f"   Attack Detection Rate (Recall): {eval_metrics['recall']:.2%}")
    print(f"   ROC-AUC Score: {eval_metrics['roc_auc']:.4f}")


if __name__ == "__main__":
    main()
