import pandas as pd
import numpy as np
import joblib

from pathlib import Path


# ============================================================
# FILE PATHS
# ============================================================

MODEL_PATH = Path("model/threat_detection_model.pkl")

FEATURE_PATH = Path("model/feature_names.pkl")

DATA_PATH = Path(
    "data/MachineLearningCVE/processed_network_data.csv"
)


# ============================================================
# LOAD MODEL
# ============================================================

print("=" * 70)
print("             🛡 NETWORK THREAT DETECTION SYSTEM")
print("=" * 70)

print("\nLoading trained model...")

model = joblib.load(MODEL_PATH)

feature_names = joblib.load(FEATURE_PATH)

print("Model loaded successfully!")


# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading network traffic dataset...")

df = pd.read_csv(DATA_PATH)

df.columns = df.columns.str.strip()

print(
    f"Loaded {len(df):,} network-flow records."
)


# ============================================================
# MENU
# ============================================================

print("\n" + "=" * 70)
print("SELECT TRAFFIC TO ANALYZE")
print("=" * 70)

print("""
1. BENIGN
2. BRUTE FORCE
3. DDoS
4. DoS
5. PORT SCAN
6. TEST ALL
0. EXIT
""")


choice = input("Enter your choice: ").strip()


# ============================================================
# CLASS SELECTION
# ============================================================

class_map = {
    "1": "BENIGN",
    "2": "BRUTE FORCE",
    "3": "DDoS",
    "4": "DoS",
    "5": "PORT SCAN"
}


# ============================================================
# FUNCTION: ANALYZE ONE RECORD
# ============================================================

def analyze_record(sample):

    # --------------------------------------------------------
    # Actual label
    # --------------------------------------------------------

    actual_label = sample["Attack_Type"].iloc[0]

    # --------------------------------------------------------
    # Prepare features
    # --------------------------------------------------------

    X = sample.drop(
        columns=[
            "Label",
            "Attack_Type"
        ],
        errors="ignore"
    )

    # Keep numeric features
    X = X.select_dtypes(
        include=[np.number]
    )

    # Make feature order identical to training
    X = X.reindex(
        columns=feature_names
    )

    # Replace infinity
    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # Replace missing values
    X = X.fillna(0)

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]

    classes = model.classes_

    confidence = probabilities.max() * 100

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    if prediction == "BENIGN":

        risk_level = "LOW"
        status = "✓ NORMAL TRAFFIC"

    elif prediction in ["BRUTE FORCE", "PORT SCAN"]:

        risk_level = "HIGH"
        status = "⚠ SUSPICIOUS TRAFFIC"

    else:

        risk_level = "CRITICAL"
        status = "🚨 POTENTIAL ATTACK"

    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("                    THREAT ANALYSIS")
    print("=" * 70)

    print(
        f"\nActual Label       : {actual_label}"
    )

    print(
        f"Predicted Threat   : {prediction}"
    )

    print(
        f"Model Probability  : {confidence:.2f}%"
    )

    print(
        f"Risk Level         : {risk_level}"
    )

    print(
        f"Status             : {status}"
    )

    print("\n" + "-" * 70)
    print("CLASS PROBABILITIES")
    print("-" * 70)

    for class_name, probability in zip(
        classes,
        probabilities
    ):

        print(
            f"{class_name:<15} : "
            f"{probability * 100:6.2f}%"
        )

    # --------------------------------------------------------
    # Prediction correctness
    # --------------------------------------------------------

    if prediction == actual_label:

        print(
            "\n✓ Prediction matches the dataset label."
        )

    else:

        print(
            "\n⚠ Prediction differs from the dataset label."
        )

    print("=" * 70)


# ============================================================
# TEST ONE CLASS
# ============================================================

if choice in class_map:

    selected_class = class_map[choice]

    print(
        f"\nSearching for a {selected_class} record..."
    )

    matching_records = df[
        df["Attack_Type"] == selected_class
    ]

    if matching_records.empty:

        print(
            f"No {selected_class} records found."
        )

    else:

        # Pick a reproducible random example
        sample = matching_records.sample(
            n=1,
            random_state=42
        )

        analyze_record(sample)


# ============================================================
# TEST ALL CLASSES
# ============================================================

elif choice == "6":

    print(
        "\nRunning one example from every class..."
    )

    for selected_class in class_map.values():

        print(
            f"\nSearching for {selected_class}..."
        )

        matching_records = df[
            df["Attack_Type"] == selected_class
        ]

        if matching_records.empty:

            print(
                f"No {selected_class} records found."
            )

            continue

        sample = matching_records.sample(
            n=1,
            random_state=42
        )

        analyze_record(sample)


# ============================================================
# EXIT
# ============================================================

elif choice == "0":

    print("\nExiting system...")

else:

    print(
        "\nInvalid choice. Please run the program again."
    )


print("\nPrediction session completed.")