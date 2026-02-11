import os
import pickle
import pandas as pd

ML_DIR = os.path.dirname(os.path.abspath(__file__))

# Load model
model = pickle.load(open(os.path.join(ML_DIR, "rf_model.pkl"), "rb"))

# Load feature order
feature_columns = pickle.load(open(os.path.join(ML_DIR, "feature_columns.pkl"), "rb"))

def predict_threat(input_dict):

    input_df = pd.DataFrame([input_dict], columns=feature_columns)

    probability = model.predict_proba(input_df)[0][1]

    if probability > 0.8:
        return "critical"
    elif probability > 0.4:
        return "suspicious"
    return "normal"




# Test block
if __name__ == "__main__":
    sample = {}

    for col in feature_columns:
        sample[col] = 100000  # large suspicious values

    print("Prediction:", predict_threat(sample))
    print("Probability of attack:", model.predict_proba(pd.DataFrame([sample], columns=feature_columns))[0][1])
