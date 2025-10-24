"""
train_model.py
Train a RandomForest on data/features.csv (only if not already trained)
and save to models/mitm_detector.joblib.
If the model already exists, it will skip retraining and just load it.
"""

import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from joblib import dump, load
from securecomm.utils import ensure_dirs

def train_model():
    ensure_dirs()

    FEAT_CSV = "data/features.csv"
    MODEL_PATH = "models/mitm_detector.joblib"

    # ✅ Step 1: If model already exists, skip training
    if os.path.exists(MODEL_PATH):
        print(f"[+] Pre-trained model found at {MODEL_PATH}. Skipping training.")
        clf = load(MODEL_PATH)
        print("[+] Model loaded successfully and ready for prediction.")
        return clf

    # ✅ Step 2: Load dataset
    if not os.path.exists(FEAT_CSV):
        print(f"[!] Feature CSV {FEAT_CSV} not found. Run feature_extractor.py first.")
        return None

    df = pd.read_csv(FEAT_CSV)
    if df.empty:
        print("[!] Feature CSV is empty. Please collect and extract features first.")
        return None

    # ✅ Step 3: Prepare X and y
    def prepare_Xy(df):
        X = df[["total_claims", "distinct_mac_count", "top_mac_ratio"]].fillna(0)
        y = df["is_spoof"].astype(int)
        return X, y

    X, y = prepare_Xy(df)

    # ✅ Step 4: Handle single-class case safely
    if y.nunique() == 1:
        print("[!] Only one class present in data. Training on single-class data (unbalanced).")
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X, y)
        dump(clf, MODEL_PATH)
        print(f"[+] Model trained (single-class) and saved to {MODEL_PATH}")
        return clf

    # ✅ Step 5: Train-test split and model training
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    # ✅ Step 6: Save model
    dump(clf, MODEL_PATH)
    print(f"[+] Model trained and saved to {MODEL_PATH}")

    return clf


if __name__ == "__main__":
    train_model()
