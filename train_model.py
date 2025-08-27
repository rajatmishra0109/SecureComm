"""
train_model.py
Train a RandomForest on data/features.csv and save to models/mitm_detector.joblib
"""

import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from joblib import dump
from securecomm.utils import ensure_dirs

def train_model():
    ensure_dirs()

    FEAT_CSV = "data/features.csv"
    MODEL_PATH = "models/mitm_detector.joblib"

    def prepare_Xy(df):
        X = df[["total_claims","distinct_mac_count","top_mac_ratio"]].fillna(0)
        y = df["is_spoof"].astype(int)
        return X, y

    if not os.path.exists(FEAT_CSV):
        print(f"[!] Feature CSV {FEAT_CSV} not found. Run feature_extractor.py first.")
        return

    df = pd.read_csv(FEAT_CSV)
    X, y = prepare_Xy(df)

    if y.nunique() == 1:
        print("[!] Only one class present in data. Need both spoofed and normal samples.")
        return

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))
    dump(clf, MODEL_PATH)
    print(f"[+] Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train_model()
