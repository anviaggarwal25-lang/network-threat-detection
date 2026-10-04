import pandas as pd
import numpy as np
import joblib

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# SETTINGS
# ============================================================

DATA_FOLDER = Path("data/MachineLearningCVE")

MAX_BENIGN_TRAIN = 20000
MAX_ATTACK_TRAIN = 30000

MAX_BENIGN_TEST = 20000
MAX_ATTACK_TEST = 20000


# ============================================================
# FILE GROUPS
# ============================================================

# We train using Monday-Thursday.
TRAIN_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
]

# We deliberately keep Friday completely separate.
TEST_FILES = [
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
]


# ============================================================
# FUNCTION TO LOAD BINARY DATA
# ============================================================

def collect_binary_data(
    filenames,
    max_benign,
    max_attack,
    dataset_name
):

    benign_parts = []
    attack_parts = []

    benign_count = 0
    attack_count = 0

    print("\n" + "=" * 70)
    print(f"COLLECTING {dataset_name.upper()} DATA")
    print("=" * 70)

    for filename in filenames:

        if benign_count >= max_benign and attack_count >= max_attack:
            break

        file_path = DATA_FOLDER / filename

        print(f"\nReading: {filename}")

        for chunk in pd.read_csv(
            file_path,
            chunksize=50000
        ):

            # Clean column names
            chunk.columns = chunk.columns.str.strip()

            # Remove missing labels
            chunk = chunk.dropna(
                subset=["Label"]
            )

            # Clean labels
            chunk["Label"] = (
                chunk["Label"]
                .astype(str)
                .str.strip()
            )

            # ------------------------------------------------
            # BENIGN
            # ------------------------------------------------

            if benign_count < max_benign:

                benign = chunk[
                    chunk["Label"].str.upper() == "BENIGN"
                ]

                remaining = max_benign - benign_count

                benign = benign.head(remaining)

                if not benign.empty:

                    benign_parts.append(benign)
                    benign_count += len(benign)

            # ------------------------------------------------
            # ATTACK
            # ------------------------------------------------

            if attack_count < max_attack:

                attack = chunk[
                    chunk["Label"].str.upper() != "BENIGN"
                ]

                remaining = max_attack - attack_count

                attack = attack.head(remaining)

                if not attack.empty:

                    attack_parts.append(attack)
                    attack_count += len(attack)

            # Stop reading if enough data collected
            if (
                benign_count >= max_benign
                and
                attack_count >= max_attack
            ):
                break

    # --------------------------------------------------------
    # COMBINE
    # --------------------------------------------------------

    data_parts = []

    if benign_parts:

        benign_df = pd.concat(
            benign_parts,
            ignore_index=True
        )

        benign_df["Binary_Label"] = "BENIGN"

        data_parts.append(benign_df)

    if attack_parts:

        attack_df = pd.concat(
            attack_parts,
            ignore_index=True
        )

        attack_df["Binary_Label"] = "ATTACK"

        data_parts.append(attack_df)

    if not data_parts:

        return pd.DataFrame()

    result = pd.concat(
        data_parts,
        ignore_index=True
    )

    # Shuffle
    result = result.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)

    print(
        f"\nBENIGN records: {benign_count:,}"
    )

    print(
        f"ATTACK records: {attack_count:,}"
    )

    return result


# ============================================================
# LOAD TRAINING DATA
# ============================================================

train_df = collect_binary_data(
    TRAIN_FILES,
    MAX_BENIGN_TRAIN,
    MAX_ATTACK_TRAIN,
    "training"
)


# ============================================================
# LOAD TEST DATA
# ============================================================

test_df = collect_binary_data(
    TEST_FILES,
    MAX_BENIGN_TEST,
    MAX_ATTACK_TEST,
    "testing"
)


# ============================================================
# CHECK DATA
# ============================================================

if train_df.empty or test_df.empty:

    print("\nERROR: Could not load the required data.")
    exit()


# ============================================================
# PREPARE FEATURES
# ============================================================

print("\n" + "=" * 70)
print("PREPARING FEATURES")
print("=" * 70)


# Save labels separately
y_train = train_df["Binary_Label"]
y_test = test_df["Binary_Label"]


# Remove label columns
X_train = train_df.drop(
    columns=[
        "Label",
        "Binary_Label"
    ],
    errors="ignore"
)

X_test = test_df.drop(
    columns=[
        "Label",
        "Binary_Label"
    ],
    errors="ignore"
)


# Keep numeric columns only
X_train = X_train.select_dtypes(
    include=[np.number]
)

# Make test columns match training columns
X_test = X_test.reindex(
    columns=X_train.columns
)


# ============================================================
# CLEAN INVALID VALUES
# ============================================================

print("Cleaning invalid values...")


X_train = X_train.replace(
    [np.inf, -np.inf],
    np.nan
)

X_test = X_test.replace(
    [np.inf, -np.inf],
    np.nan
)


# Use TRAINING medians for both datasets
train_medians = X_train.median()

X_train = X_train.fillna(
    train_medians
)

X_test = X_test.fillna(
    train_medians
)

X_train = X_train.fillna(0)
X_test = X_test.fillna(0)


print(
    f"Features used: {X_train.shape[1]}"
)


# ============================================================
# TRAIN MODEL
# ============================================================

print("\n" + "=" * 70)
print("TRAINING DAY-AWARE MODEL")
print("=" * 70)

print(
    "\nTraining on Monday-Thursday..."
)

print(
    "Testing only on Friday..."
)


model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(
    X_train,
    y_train
)


print("\nTraining complete!")


# ============================================================
# PREDICTIONS
# ============================================================

print("\nGenerating predictions...")

y_pred = model.predict(
    X_test
)


# ============================================================
# RESULTS
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)


print("\n" + "=" * 70)
print("DAY-AWARE GENERALIZATION RESULTS")
print("=" * 70)


print(
    f"\nAccuracy: {accuracy * 100:.2f}%"
)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred
    )
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

print("\nConfusion Matrix:")

labels = [
    "BENIGN",
    "ATTACK"
]

cm = confusion_matrix(
    y_test,
    y_pred,
    labels=labels
)

print("\nLabels:")
print(labels)

print("\nMatrix:")
print(cm)


# ============================================================
# SAVE RESULTS
# ============================================================

results_folder = Path("model")
results_folder.mkdir(
    exist_ok=True
)

joblib.dump(
    model,
    results_folder / "day_aware_binary_model.pkl"
)

joblib.dump(
    list(X_train.columns),
    results_folder / "binary_feature_names.pkl"
)


print("\n" + "=" * 70)
print("DAY-AWARE MODEL SAVED")
print("=" * 70)

print(
    "\nModel:"
)

print(
    "model/day_aware_binary_model.pkl"
)

print("\nEvaluation complete!")