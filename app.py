from flask import Flask, render_template, jsonify, request, Response
import os
import json
import pickle

import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "model"
)

DATASET_PATH = os.path.join(
    DATA_DIR,
    "heldout_test_data.csv"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "threat_detection_model.pkl"
)

FEATURE_NAMES_PATH = os.path.join(
    MODEL_DIR,
    "feature_names.pkl"
)


# ============================================================
# GLOBAL VARIABLES
# ============================================================

model = None

feature_names = []

test_df = pd.DataFrame()

X_test = None
y_test = None

predictions = None
prediction_probabilities = None

model_classes = []

traffic_records = []

traffic_json = None


# ============================================================
# STANDARD LABELS
# ============================================================

EXPECTED_LABELS = [
    "BENIGN",
    "BRUTE FORCE",
    "DDoS",
    "DoS",
    "PORT SCAN"
]


# ============================================================
# LABEL NORMALIZATION
# ============================================================

def normalize_label(label):

    if label is None:
        return "UNKNOWN"

    value = str(label).strip()

    normalized = (
        value
        .upper()
        .replace("_", " ")
        .replace("-", " ")
    )

    if normalized == "BENIGN":
        return "BENIGN"

    if normalized in [
        "BRUTE FORCE",
        "BRUTEFORCE"
    ]:
        return "BRUTE FORCE"

    if normalized == "DDOS":
        return "DDoS"

    if normalized == "DOS":
        return "DoS"

    if normalized in [
        "PORT SCAN",
        "PORTSCAN"
    ]:
        return "PORT SCAN"

    return value


# ============================================================
# JSON-SAFE VALUE
# ============================================================

def safe_value(value):

    if value is None:
        return None

    try:

        if pd.isna(value):
            return None

    except Exception:
        pass

    if isinstance(
        value,
        (np.integer,)
    ):
        return int(value)

    if isinstance(
        value,
        (np.floating,)
    ):

        number = float(value)

        if not np.isfinite(number):
            return None

        return number

    if isinstance(
        value,
        (np.bool_,)
    ):
        return bool(value)

    return value


# ============================================================
# LOAD EVERYTHING
# ============================================================

def load_resources():

    global model
    global feature_names
    global test_df
    global X_test
    global y_test
    global predictions
    global prediction_probabilities
    global model_classes
    global traffic_records
    global traffic_json

    print()
    print("=" * 65)
    print("NETWORK THREAT DETECTION SYSTEM")
    print("=" * 65)

    # ========================================================
    # LOAD MODEL
    # ========================================================

    if not os.path.exists(MODEL_PATH):

        raise FileNotFoundError(
            f"Model file not found:\n{MODEL_PATH}"
        )

    with open(
        MODEL_PATH,
        "rb"
    ) as file:

        model = pickle.load(file)

    print(
        f"[OK] Random Forest model loaded"
    )

    # ========================================================
    # LOAD FEATURE NAMES
    # ========================================================

    if not os.path.exists(
        FEATURE_NAMES_PATH
    ):

        raise FileNotFoundError(
            f"Feature names file not found:\n"
            f"{FEATURE_NAMES_PATH}"
        )

    with open(
        FEATURE_NAMES_PATH,
        "rb"
    ) as file:

        feature_names = pickle.load(file)

    feature_names = list(
        feature_names
    )

    print(
        f"[OK] Feature names loaded: "
        f"{len(feature_names)}"
    )

    # ========================================================
    # LOAD DATASET
    # ========================================================

    if not os.path.exists(
        DATASET_PATH
    ):

        raise FileNotFoundError(
            f"Dataset file not found:\n"
            f"{DATASET_PATH}"
        )

    test_df = pd.read_csv(
        DATASET_PATH
    )

    print(
        f"[OK] Held-out dataset loaded: "
        f"{len(test_df):,} records"
    )

    # ========================================================
    # FIND TARGET COLUMN
    # ========================================================

    if "Attack_Type" not in test_df.columns:

        possible_targets = [
            "attack_type",
            "Attack Type",
            "Label",
            "label"
        ]

        target_column = None

        for column in possible_targets:

            if column in test_df.columns:

                target_column = column
                break

        if target_column is None:

            raise ValueError(
                "Could not find Attack_Type "
                "column in dataset."
            )

        test_df["Attack_Type"] = (
            test_df[target_column]
        )

    # ========================================================
    # PREPARE MODEL FEATURES
    # ========================================================

    X = test_df.copy()

    # Remove target
    if "Attack_Type" in X.columns:

        X = X.drop(
            columns=["Attack_Type"]
        )

    # Remove non-feature columns
    # ONLY when they aren't part of saved features.

    removable_columns = [
        "record_id",
        "Record",
        "id",
        "Label",
        "label",
        "attack_type",
        "Attack Type"
    ]

    for column in removable_columns:

        if (
            column in X.columns
            and column not in feature_names
        ):

            X = X.drop(
                columns=[column]
            )

    # ========================================================
    # ENSURE ALL MODEL FEATURES EXIST
    # ========================================================

    for feature in feature_names:

        if feature not in X.columns:

            X[feature] = 0

    # Exact feature order
    X = X[
        feature_names
    ]

    # ========================================================
    # NUMERIC CONVERSION
    # ========================================================

    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    X = X.fillna(0)

    X_test = X

    # ========================================================
    # ACTUAL LABELS
    # ========================================================

    y_test = (
        test_df["Attack_Type"]
        .apply(normalize_label)
    )

    # ========================================================
    # MODEL PREDICTIONS
    # ========================================================

    predictions_raw = model.predict(
        X_test
    )

    predictions = np.array([
        normalize_label(value)
        for value in predictions_raw
    ])

    print(
        "[OK] Predictions generated"
    )

    # ========================================================
    # MODEL PROBABILITIES
    # ========================================================

    if hasattr(
        model,
        "predict_proba"
    ):

        prediction_probabilities = (
            model.predict_proba(X_test)
        )

        print(
            "[OK] Prediction probabilities generated"
        )

    else:

        prediction_probabilities = None

        print(
            "[WARNING] Model does not support "
            "predict_proba()"
        )

    # ========================================================
    # MODEL CLASSES
    # ========================================================

    if hasattr(
        model,
        "classes_"
    ):

        model_classes = [
            normalize_label(value)
            for value in model.classes_
        ]

    else:

        model_classes = sorted(
            list(
                set(
                    y_test.tolist()
                )
            )
        )

    print(
        f"[OK] Model classes: "
        f"{model_classes}"
    )

    # ========================================================
    # BUILD TRAFFIC CACHE
    # ========================================================

    print(
        "[...] Preparing Traffic Explorer data..."
    )

    build_traffic_cache()

    print(
        "[OK] Traffic Explorer cache ready"
    )

    print()
    print("=" * 65)
    print("SYSTEM READY")
    print("=" * 65)
    print()


# ============================================================
# BUILD TRAFFIC CACHE
# ============================================================

def build_traffic_cache():

    global traffic_records
    global traffic_json

    traffic_records = []

    # Convert the dataframe to records only once.
    raw_records = test_df.to_dict(
        orient="records"
    )

    for index, raw_record in enumerate(
        raw_records
    ):

        record = {
            "record_id": int(index + 1)
        }

        for column, value in raw_record.items():

            if column == "Attack_Type":

                record[
                    "Attack_Type"
                ] = normalize_label(value)

            else:

                record[column] = safe_value(
                    value
                )

        traffic_records.append(
            record
        )

    labels = test_df[
        "Attack_Type"
    ].apply(
        normalize_label
    )

    total = len(labels)

    benign = int(
        (labels == "BENIGN").sum()
    )

    attacks = total - benign

    payload = {
        "records": traffic_records,

        "statistics": {
            "total": total,
            "benign": benign,
            "attacks": attacks
        }
    }

    # Serialize ONCE.
    traffic_json = json.dumps(
        payload,
        allow_nan=False,
        separators=(
            ",",
            ":"
        )
    )


# ============================================================
# PREPARE ONE FEATURE VECTOR
# ============================================================

def prepare_feature_vector(row):

    values = []

    for feature in feature_names:

        value = row.get(
            feature,
            0
        )

        try:

            value = float(value)

            if not np.isfinite(value):

                value = 0.0

        except (
            ValueError,
            TypeError
        ):

            value = 0.0

        values.append(
            value
        )

    return np.array(
        values,
        dtype=float
    ).reshape(
        1,
        -1
    )


# ============================================================
# FIND SCENARIO RECORD
# ============================================================

def find_scenario_record(
    scenario
):

    requested_label = normalize_label(
        scenario
    )

    labels = (
        test_df["Attack_Type"]
        .apply(normalize_label)
    )

    matches = np.where(
        labels.values == requested_label
    )[0]

    if len(matches) == 0:

        return None

    return int(
        matches[0]
    )


# ============================================================
# GET SEVERITY
# ============================================================

def get_severity(label):

    normalized = normalize_label(
        label
    )

    if normalized in [
        "DDoS",
        "DoS"
    ]:

        return "CRITICAL"

    if normalized in [
        "BRUTE FORCE",
        "PORT SCAN"
    ]:

        return "HIGH"

    if normalized == "BENIGN":

        return "LOW"

    return "MEDIUM"


# ============================================================
# GET MODEL CONFIDENCE FOR RECORD
# ============================================================

def get_record_confidence(
    index,
    prediction
):

    if prediction_probabilities is None:

        return 100.0

    if index >= len(
        prediction_probabilities
    ):

        return 0.0

    probabilities = (
        prediction_probabilities[index]
    )

    if not hasattr(
        model,
        "classes_"
    ):

        return 0.0

    for class_name, probability in zip(
        model.classes_,
        probabilities
    ):

        normalized_class = normalize_label(
            class_name
        )

        if normalized_class == prediction:

            return float(
                probability
            ) * 100.0

    return 0.0


# ============================================================
# OVERVIEW API
# ============================================================

@app.route(
    "/api/overview"
)
def api_overview():

    labels = (
        test_df["Attack_Type"]
        .apply(normalize_label)
    )

    total = len(labels)

    benign = int(
        (labels == "BENIGN").sum()
    )

    attacks = (
        total - benign
    )

    distribution = {}

    for label in EXPECTED_LABELS:

        distribution[label] = int(
            (labels == label).sum()
        )

    return jsonify({

        "total": total,

        "benign": benign,

        "attacks": attacks,

        "distribution":
            distribution
    })


# ============================================================
# THREAT ANALYSIS API
# ============================================================

@app.route(
    "/api/analyze",
    methods=["POST"]
)
def api_analyze():

    try:

        data = (
            request.get_json(
                silent=True
            )
            or {}
        )

        scenario = data.get(
            "scenario"
        )

        if not scenario:

            return jsonify({
                "error":
                    "Please select a traffic scenario."
            }), 400

        index = find_scenario_record(
            scenario
        )

        if index is None:

            return jsonify({
                "error":
                    f"No dataset record found "
                    f"for scenario: {scenario}"
            }), 404

        # ====================================================
        # GET RECORD
        # ====================================================

        row = test_df.iloc[
            index
        ]

        actual_label = normalize_label(
            row["Attack_Type"]
        )

        # ====================================================
        # MODEL INPUT
        # ====================================================

        X_row = prepare_feature_vector(
            row
        )

        # ====================================================
        # PREDICTION
        # ====================================================

        prediction_raw = model.predict(
            X_row
        )[0]

        prediction = normalize_label(
            prediction_raw
        )

        # ====================================================
        # CLASS PROBABILITIES
        # ====================================================

        probabilities = {}

        if hasattr(
            model,
            "predict_proba"
        ):

            probability_array = (
                model.predict_proba(
                    X_row
                )[0]
            )

            for class_name, probability in zip(
                model.classes_,
                probability_array
            ):

                normalized_class = normalize_label(
                    class_name
                )

                probabilities[
                    normalized_class
                ] = round(
                    float(probability) * 100,
                    4
                )

        else:

            probabilities[
                prediction
            ] = 100.0

        # Add missing expected classes
        # so the frontend always receives a
        # consistent probability object.

        for label in EXPECTED_LABELS:

            if label not in probabilities:

                probabilities[label] = 0.0

        # ====================================================
        # CONFIDENCE
        # ====================================================

        confidence = probabilities.get(
            prediction,
            0.0
        )

        # ====================================================
        # FEATURES
        # ====================================================

        features = {}

        for feature in feature_names:

            features[feature] = safe_value(
                row.get(
                    feature,
                    0
                )
            )

        # ====================================================
        # RESPONSE
        # ====================================================

        return jsonify({

            "prediction":
                prediction,

            "confidence":
                round(
                    float(confidence),
                    2
                ),

            "actual_label":
                actual_label,

            "probabilities":
                probabilities,

            "features":
                features
        })

    except Exception as error:

        print(
            "[ERROR] Analysis:",
            repr(error)
        )

        return jsonify({
            "error": str(error)
        }), 500


# ============================================================
# TRAFFIC EXPLORER API
# ============================================================

@app.route(
    "/api/traffic"
)
def api_traffic():

    try:

        # IMPORTANT:
        # traffic_json was prepared once during startup.
        # We don't rebuild 18,767 records here.

        return Response(
            traffic_json,
            mimetype="application/json"
        )

    except Exception as error:

        print(
            "[ERROR] Traffic:",
            repr(error)
        )

        return jsonify({
            "error": str(error)
        }), 500


# ============================================================
# ALERTS API
# ============================================================

@app.route(
    "/api/alerts"
)
def api_alerts():

    try:

        alerts = []

        labels = (
            test_df["Attack_Type"]
            .apply(normalize_label)
        )

        # ====================================================
        # CREATE ATTACK ALERTS
        # ====================================================

        for index in range(
            len(test_df)
        ):

            actual_label = labels.iloc[
                index
            ]

            # No alert for benign traffic.
            if actual_label == "BENIGN":

                continue

            prediction = predictions[
                index
            ]

            confidence = (
                get_record_confidence(
                    index,
                    prediction
                )
            )

            severity = get_severity(
                prediction
            )

            row = test_df.iloc[
                index
            ]

            # =================================================
            # SOURCE
            # =================================================

            if "Source IP" in row.index:

                source = row[
                    "Source IP"
                ]

            elif "Source" in row.index:

                source = row[
                    "Source"
                ]

            else:

                source = "—"

            # =================================================
            # DESTINATION
            # =================================================

            if "Destination IP" in row.index:

                destination = row[
                    "Destination IP"
                ]

            elif "Destination" in row.index:

                destination = row[
                    "Destination"
                ]

            else:

                destination = "—"

            # =================================================
            # ALERT OBJECT
            # =================================================

            alert = {

                "alert_id":
                    f"ALT-{index + 1:04d}",

                "record_id":
                    index + 1,

                "threat_type":
                    prediction,

                "severity":
                    severity,

                "confidence":
                    round(
                        confidence,
                        2
                    ),

                "status":
                    "NEW",

                "source":
                    safe_value(source),

                "destination":
                    safe_value(destination),

                "description":
                    (
                        f"The model identified "
                        f"{prediction} traffic "
                        f"requiring review."
                    )
            }

            alerts.append(
                alert
            )

        # ====================================================
        # ALERT STATISTICS
        # ====================================================

        critical = sum(
            1
            for alert in alerts
            if alert["severity"] ==
            "CRITICAL"
        )

        high = sum(
            1
            for alert in alerts
            if alert["severity"] ==
            "HIGH"
        )

        medium_low = sum(
            1
            for alert in alerts
            if alert["severity"] in [
                "MEDIUM",
                "LOW"
            ]
        )

        return jsonify({

            "alerts":
                alerts,

            "statistics": {

                "total":
                    len(alerts),

                "critical":
                    critical,

                "high":
                    high,

                "medium_low":
                    medium_low
            }
        })

    except Exception as error:

        print(
            "[ERROR] Alerts:",
            repr(error)
        )

        return jsonify({
            "error": str(error)
        }), 500


# ============================================================
# MODEL PERFORMANCE API
# ============================================================

@app.route(
    "/api/performance"
)
def api_performance():

    try:

        # ====================================================
        # OVERALL METRICS
        # ====================================================

        accuracy = accuracy_score(
            y_test,
            predictions
        )

        precision = precision_score(
            y_test,
            predictions,
            average="weighted",
            zero_division=0
        )

        recall = recall_score(
            y_test,
            predictions,
            average="weighted",
            zero_division=0
        )

        f1 = f1_score(
            y_test,
            predictions,
            average="weighted",
            zero_division=0
        )

        # ====================================================
        # CLASSIFICATION REPORT
        # ====================================================

        report = classification_report(
            y_test,
            predictions,
            output_dict=True,
            zero_division=0
        )

        # ====================================================
        # ORDERED CLASSES
        # ====================================================

        ordered_classes = []

        for label in model_classes:

            if label not in ordered_classes:

                ordered_classes.append(
                    label
                )

        for label in sorted(
            set(
                y_test.tolist()
            )
        ):

            if label not in ordered_classes:

                ordered_classes.append(
                    label
                )

        # ====================================================
        # PER-CLASS PERFORMANCE
        # ====================================================

        class_performance = []

        for label in ordered_classes:

            if label not in report:

                continue

            metrics = report[
                label
            ]

            class_performance.append({

                "class":
                    label,

                "precision":
                    round(
                        float(
                            metrics.get(
                                "precision",
                                0
                            )
                        ),
                        6
                    ),

                "recall":
                    round(
                        float(
                            metrics.get(
                                "recall",
                                0
                            )
                        ),
                        6
                    ),

                "f1_score":
                    round(
                        float(
                            metrics.get(
                                "f1-score",
                                0
                            )
                        ),
                        6
                    ),

                "support":
                    int(
                        metrics.get(
                            "support",
                            0
                        )
                    )
            })

        # ====================================================
        # CONFUSION MATRIX
        # ====================================================

        matrix = confusion_matrix(
            y_test,
            predictions,
            labels=ordered_classes
        )

        confusion_matrix_data = [
            [
                int(value)
                for value in row
            ]
            for row in matrix.tolist()
        ]

        # ====================================================
        # RESPONSE
        # ====================================================

        return jsonify({

            "metrics": {

                "accuracy":
                    float(accuracy),

                "precision":
                    float(precision),

                "recall":
                    float(recall),

                "f1_score":
                    float(f1)
            },

            "model": {

                "algorithm":
                    "Random Forest",

                "classification_type":
                    "Multi-Class",

                "features":
                    len(feature_names),

                "classes":
                    ordered_classes
            },

            "dataset": {

                "test_records":
                    int(len(test_df)),

                "features":
                    len(feature_names),

                "classes":
                    len(ordered_classes)
            },

            "features":
                len(feature_names),

            "classes":
                ordered_classes,

            "test_records":
                int(len(test_df)),

            "class_performance":
                class_performance,

            "confusion_matrix":
                confusion_matrix_data
        })

    except Exception as error:

        print(
            "[ERROR] Performance:",
            repr(error)
        )

        return jsonify({
            "error": str(error)
        }), 500


# ============================================================
# SYSTEM API
# ============================================================

@app.route(
    "/api/system"
)
def api_system():

    return jsonify({

        "application":
            "Network Threat Detection System",

        "model":
            "Random Forest",

        "model_loaded":
            model is not None,

        "dataset_loaded":
            not test_df.empty,

        "dataset_records":
            int(len(test_df)),

        "features":
            int(len(feature_names)),

        "classes":
            model_classes,

        "dataset_path":
            DATASET_PATH,

        "model_path":
            MODEL_PATH
    })


# ============================================================
# OPTIONAL SCENARIO API
# ============================================================

@app.route(
    "/api/scenarios"
)
def api_scenarios():

    dataset_labels = set(
        test_df[
            "Attack_Type"
        ]
        .apply(normalize_label)
        .tolist()
    )

    scenarios = []

    for label in EXPECTED_LABELS:

        scenarios.append({

            "name":
                label,

            "available":
                label in dataset_labels
        })

    return jsonify({

        "scenarios":
            scenarios
    })


# ============================================================
# PAGE ROUTES
# ============================================================

@app.route("/")
def home():

    return render_template(
        "overview.html"
    )


@app.route("/overview")
def overview_page():

    return render_template(
        "overview.html"
    )


@app.route("/analysis")
def analysis_page():

    return render_template(
        "analysis.html"
    )


@app.route("/traffic")
def traffic_page():

    return render_template(
        "traffic.html"
    )


@app.route("/alerts")
def alerts_page():

    return render_template(
        "alerts.html"
    )


@app.route("/performance")
def performance_page():

    return render_template(
        "performance.html"
    )


@app.route("/system")
def system_page():

    return render_template(
        "system.html"
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "error":
            "Resource not found."
    }), 404


@app.errorhandler(500)
def server_error(error):

    return jsonify({
        "error":
            "Internal server error."
    }), 500


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    try:

        load_resources()

        print(
            "Starting Flask server..."
        )

        print(
            "Open: "
            "http://127.0.0.1:5000"
        )

        app.run(
            host="127.0.0.1",
            port=5000,
            debug=True
        )

    except Exception as error:

        print()
        print("=" * 65)
        print("APPLICATION STARTUP FAILED")
        print("=" * 65)

        print()
        print(
            f"Error: {error}"
        )

        print()
        print(
            "Required files:"
        )

        print(
            f"  Dataset : {DATASET_PATH}"
        )

        print(
            f"  Model   : {MODEL_PATH}"
        )

        print(
            f"  Features: {FEATURE_NAMES_PATH}"
        )

        print("=" * 65)