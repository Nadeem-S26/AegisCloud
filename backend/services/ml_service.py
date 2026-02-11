import os
import pickle
import pandas as pd
import numpy as np

# Resolve paths relative to project root (AegisCloud/)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODEL_PATH = os.path.join(PROJECT_ROOT, "ml", "rf_model.pkl")
FEATURES_PATH = os.path.join(PROJECT_ROOT, "ml", "feature_columns.pkl")
SCALER_PATH = os.path.join(PROJECT_ROOT, "ml", "feature_scaler.pkl")

model = None
feature_columns = None
scaler = None

def load_model():
    """Load the trained RandomForest model, feature columns, and feature scaler."""
    global model, feature_columns, scaler
    try:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        with open(FEATURES_PATH, "rb") as f:
            feature_columns = pickle.load(f)
        
        # Load scaler if available (used for normalization)
        scaler = None
        if os.path.exists(SCALER_PATH):
            try:
                with open(SCALER_PATH, "rb") as f:
                    scaler = pickle.load(f)
                print(f"✅ Model loaded successfully ({len(feature_columns)} features with normalization)")
            except Exception as e:
                print(f"⚠️  Scaler not found, using raw features: {e}")
                print(f"✅ Model loaded successfully ({len(feature_columns)} features)")
        else:
            print(f"✅ Model loaded successfully ({len(feature_columns)} features)")
    except FileNotFoundError as e:
        print(f"⚠️  Model files not found: {e}")
        print("   Run ml/dataset.py first to train the model.")
        model = None
        feature_columns = None
        scaler = None

# Load model on import
load_model()

def predict_log(log_data: dict) -> tuple:
    """
    Predict threat level from a log entry dict.
    Returns (label, probability) tuple.
    
    Process:
    1. Extract specified features from log data
    2. Normalize using trained scaler (if available)
    3. Run through RandomForest model
    4. Return threat classification
    """
    if model is None or feature_columns is None:
        return "Unknown", 0.0

    # Build feature vector: map log fields to model features, default 0
    input_dict = {}
    for col in feature_columns:
        input_dict[col] = log_data.get(col, 0)

    input_df = pd.DataFrame([input_dict], columns=feature_columns)
    
    # Apply scaler if available (for normalized predictions)
    if scaler is not None:
        try:
            input_df_scaled = scaler.transform(input_df)
            input_df = pd.DataFrame(input_df_scaled, columns=feature_columns)
        except Exception as e:
            print(f"⚠️  Scaler error, using raw features: {e}")
    
    probability = model.predict_proba(input_df)[0][1]  # P(attack)

    # Classification thresholds
    if probability > 0.8:
        label = "Attack"
    elif probability > 0.4:
        label = "Suspicious"
    else:
        label = "Normal"

    return label, round(float(probability), 4)
