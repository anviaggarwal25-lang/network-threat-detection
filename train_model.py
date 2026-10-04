import os
import pickle
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# ============================================================
# CONFIGURATION
# ============================================================

DATA_FILE = "data/MachineLearningCVE/processed_network_data.csv"

MODEL_DIR = "model"
MODEL_FILE = os.path.join(MODEL_DIR, "threat_detection_model.pkl")
FEATURE_FILE = os.path.join(MODEL_DIR, "feature_names.pkl")

HELDOUT_FILE = "data/heldout_test_data.csv"

LABEL_COLUMN = "Attack_Type"


# ============================================================
# CREATE REQUIRED DIRECTORIES
# ============================================================

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs("data", exist_ok=True)


# ============================================================
# HEADER
# ============================================================

print("=" * 70)
print("NETWORK THREAT DETECTION - MODEL TRAINING")
print("=" * 70)


# ============================================================
# 1. LOAD DATASET
# ============================================================

print("\n[1/7] Loading processed dataset...")

if not os.path.exists(DATA_FILE):
    print("\nERROR: Dataset not found!")
    print(f"Expected location: {DATA_FILE}")
    raise FileNotFoundError(DATA_FILE)

df = pd.read_csv(DATA_FILE)

print(f"Dataset loaded: {len(df):,} records")
print(f"Total columns: {len(df.columns)}")


# ============================================================
# 2. CHECK CLASS DISTRIBUTION
# ============================================================

print("\n[2/7] Class distribution:")

if LABEL_COLUMN not in df.columns:
    print(f"\nERROR: '{LABEL_COLUMN}' column not found!")
    print("Available columns:")
    print(df.columns.tolist())
    raise ValueError(f"Missing label column: {LABEL_COLUMN}")

print(df[LABEL_COLUMN].value_counts())


# ============================================================
# 3. PREPARE FEATURES
# ============================================================

print("\n[3/7] Preparing features...")

# Separate labels from features
y = df[LABEL_COLUMN].astype(str)

X_raw = df.drop(columns=[LABEL_COLUMN])

# Keep only numeric columns
X = X_raw.select_dtypes(include=[np.number]).copy()

print(f"Numeric features available: {X.shape[1]}")


# ============================================================
# 4. CLEAN DATA
# ============================================================

print("\n[4/7] Cleaning data...")

# Replace infinite values
X = X.replace([np.inf, -np.inf], np.nan)

# Replace missing values
X = X.fillna(0)

# Make sure everything is numeric
X = X.apply(pd.to_numeric, errors="coerce")

# Fill anything that became NaN
X = X.fillna(0)

print("Data cleaning complete.")


# ============================================================
# SAVE FEATURE NAMES
# ============================================================

feature_names = X.columns.tolist()

with open(FEATURE_FILE, "wb") as f:
    pickle.dump(feature_names, f)

print(f"Feature list saved: {FEATURE_FILE}")


# ============================================================
# 5. CREATE TRAINING AND TESTING DATASETS
# ============================================================

print("\n[5/7] Creating training and testing datasets...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"Training records: {len(X_train):,}")
print(f"Testing records: {len(X_test):,}")


# ============================================================
# SAVE HELD-OUT TEST DATA
# ============================================================
#
# IMPORTANT:
# These records were NOT used for training.
# They are kept separately so the web application can
# demonstrate predictions on unseen test records.
#
# ============================================================

print("\nSaving held-out test data for web demonstration...")

test_data = X_test.copy()

# Add the real dataset label
test_data[LABEL_COLUMN] = y_test.values

test_data.to_csv(
    HELDOUT_FILE,
    index=False
)

print("Held-out test data saved successfully!")
print(f"Location: {HELDOUT_FILE}")
print(f"Records available for web demo: {len(test_data):,}")


# ============================================================
# 6. TRAIN RANDOM FOREST MODEL
# ============================================================

print("\n[6/7] Training Random Forest model...")

model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

print("Random Forest training complete.")


# ============================================================
# 7. EVALUATE MODEL
# ============================================================

print("\n[7/7] Evaluating model...")

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\n" + "=" * 70)
print("MODEL RESULTS")
print("=" * 70)

print(f"\nAccuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)

print("\nConfusion Matrix:")

labels = sorted(y.unique())

print("\nLabels:")
print(labels)

print("\nMatrix:")
print(confusion_matrix(y_test, y_pred, labels=labels))


# ============================================================
# SAVE TRAINED MODEL
# ============================================================

with open(MODEL_FILE, "wb") as f:
    pickle.dump(model, f)


# ============================================================
# FINAL INFORMATION
# ============================================================

print("\n" + "=" * 70)
print("MODEL SAVED")
print("=" * 70)

print(f"\nModel:")
print(MODEL_FILE)

print("\nFeature list:")
print(FEATURE_FILE)

print("\nHeld-out test data:")
print(HELDOUT_FILE)

print(f"\nTraining records: {len(X_train):,}")
print(f"Testing records: {len(X_test):,}")
print(f"Total records: {len(df):,}")

print("\nTraining process completed successfully!")
print("=" * 70)