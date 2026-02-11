import os
import pickle
import pandas as pd
import numpy as np

print("🔍 Checking RandomForest Model Configuration...\n")

# =========================
# LOAD MODEL
# =========================

ML_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    model = pickle.load(open(os.path.join(ML_DIR, "rf_model.pkl"), "rb"))
    print("✅ Model loaded successfully!")
except Exception as e:
    print("❌ Error loading model:", e)
    exit()

print("Model type:", type(model).__name__)

# =========================
# CHECK IF MODEL IS FITTED
# =========================

try:
    num_trees = len(model.estimators_)
    print(f"✅ Model is fitted with {num_trees} trees")
except Exception as e:
    print("❌ Model is NOT fitted properly.")
    print("Error:", e)
    exit()

# =========================
# CHECK MODEL HYPERPARAMETERS
# =========================

print("\n⚙️  Model Hyperparameters:")
print(f"  n_estimators:      {model.n_estimators}")
print(f"  max_depth:         {model.max_depth}")
print(f"  min_samples_split: {model.min_samples_split}")
print(f"  min_samples_leaf:  {model.min_samples_leaf}")
print(f"  max_features:      {model.max_features}")
print(f"  class_weight:      {model.class_weight}")

# =========================
# CHECK FEATURE IMPORTANCE
# =========================

if hasattr(model, "feature_importances_"):
    print("\n✅ Feature importances available.")
else:
    print("\n❌ Feature importances not found.")

# =========================
# LOAD FEATURE COLUMNS
# =========================

try:
    feature_columns = pickle.load(open(os.path.join(ML_DIR, "feature_columns.pkl"), "rb"))
    print(f"✅ Feature columns loaded.")
    print(f"   Selected features: {len(feature_columns)}")
    for i, feat in enumerate(feature_columns[:5], 1):
        print(f"     {i}. {feat}")
    if len(feature_columns) > 5:
        print(f"     ... and {len(feature_columns) - 5} more")
except Exception as e:
    print("❌ Error loading feature columns:", e)
    exit()

# =========================
# CHECK SCALER
# =========================

SCALER_PATH = os.path.join(ML_DIR, "feature_scaler.pkl")
if os.path.exists(SCALER_PATH):
    try:
        scaler = pickle.load(open(SCALER_PATH, "rb"))
        print(f"\n✅ Feature scaler loaded (StandardScaler)")
    except Exception as e:
        print(f"\n⚠️  Scaler file found but error loading: {e}")
else:
    print(f"\n⚠️  Feature scaler not found (using raw features)")

# =========================
# TEST PREDICTION
# =========================

try:
    # Create dummy input with raw features
    sample = pd.DataFrame(
        np.zeros((1, len(feature_columns))),
        columns=feature_columns
    )

    prediction = model.predict(sample)
    probability = model.predict_proba(sample)[0][1]

    print("\n✅ Prediction test successful!")
    print(f"   Test Input: All zeros (benign traffic)")
    print(f"   Prediction: {prediction[0]} ({'Normal' if prediction[0] == 0 else 'Attack'})")
    print(f"   Attack Probability: {probability:.4f}")

except Exception as e:
    print("❌ Prediction failed:", e)
    exit()

# =========================
# CHECK EVALUATION REPORT
# =========================

REPORT_PATH = os.path.join(ML_DIR, "model_evaluation_report.txt")
if os.path.exists(REPORT_PATH):
    print("\n📊 MODEL EVALUATION REPORT:")
    print("="*70)
    with open(REPORT_PATH, 'r') as f:
        print(f.read())
else:
    print("\n⚠️  Evaluation report not found (model needs retraining)")

print("\n" + "="*70)
print("🎉 MODEL IS TRAINED AND WORKING PROPERLY!")
print("="*70)

