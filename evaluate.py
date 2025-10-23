"""
evaluate.py
Quick script to evaluate a saved model against features.csv
"""

import os
import pandas as pd
from joblib import load
from sklearn.metrics import classification_report, accuracy_score
from securecomm.train_model import prepare_Xy

MODEL_PATH = "models/mitm_detector.joblib"
FEAT_CSV = "data/features.csv"

if not os.path.exists(MODEL_PATH):
    print("[!] Model not found. Run train_model.py first.")
    exit(1)
if not os.path.exists(FEAT_CSV):
    print("[!] Feature CSV not found. Run feature_extractor.py first.")
    exit(1)

df = pd.read_csv(FEAT_CSV)
X, y = prepare_Xy(df)
model = load(MODEL_PATH)
y_pred = model.predict(X)
print("Accuracy:", accuracy_score(y, y_pred))
print(classification_report(y, y_pred))
