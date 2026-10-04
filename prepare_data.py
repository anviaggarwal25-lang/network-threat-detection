import pandas as pd
from pathlib import Path

# --------------------------------------------------
# PROJECT SETTINGS
# --------------------------------------------------

DATA_FOLDER = Path("data/MachineLearningCVE")

# Maximum number of records we want from each class
MAX_PER_CLASS = 20000

# --------------------------------------------------
# FILES WE WILL USE
# --------------------------------------------------

files = {
    "BENIGN": [
        "Monday-WorkingHours.pcap_ISCX.csv"
    ],

    "BRUTE FORCE": [
        "Tuesday-WorkingHours.pcap_ISCX.csv"
    ],

    "DoS": [
        "Wednesday-workingHours.pcap_ISCX.csv"
    ],

    "DDoS": [
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    ],

    "PORT SCAN": [
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    ]
}

# --------------------------------------------------
# STORAGE
# --------------------------------------------------

all_data = []

print("=" * 70)
print("NETWORK THREAT DETECTION - DATA PREPARATION")
print("=" * 70)

# --------------------------------------------------
# READ DATA
# --------------------------------------------------

for target_class, file_list in files.items():

    print(f"\nProcessing class: {target_class}")

    class_data = []

    for filename in file_list:

        file_path = DATA_FOLDER / filename

        print(f"Reading: {filename}")

        # Read file in chunks so we don't overload memory
        for chunk in pd.read_csv(file_path, chunksize=50000):

            # Remove spaces from column names
            chunk.columns = chunk.columns.str.strip()

            # Remove rows with missing labels
            chunk = chunk.dropna(subset=["Label"])

            # Clean label text
            chunk["Label"] = chunk["Label"].astype(str).str.strip()

            # --------------------------------------------------
            # SELECT RECORDS FOR THIS CLASS
            # --------------------------------------------------

            if target_class == "BENIGN":

                selected = chunk[
                    chunk["Label"].str.upper() == "BENIGN"
                ]

            elif target_class == "BRUTE FORCE":

                selected = chunk[
                    chunk["Label"].str.contains(
                        "Patator",
                        case=False,
                        na=False
                    )
                ]

            elif target_class == "DoS":

                selected = chunk[
                    chunk["Label"].str.contains(
                        "DoS",
                        case=False,
                        na=False
                    )
                ]

            elif target_class == "DDoS":

                selected = chunk[
                    chunk["Label"].str.contains(
                        "DDoS",
                        case=False,
                        na=False
                    )
                ]

            elif target_class == "PORT SCAN":

                selected = chunk[
                    chunk["Label"].str.contains(
                        "PortScan",
                        case=False,
                        na=False
                    )
                ]

            else:
                selected = pd.DataFrame()

            # Add selected records
            if not selected.empty:

                class_data.append(selected)

                current_count = sum(
                    len(x) for x in class_data
                )

                if current_count >= MAX_PER_CLASS:
                    break

        # Stop reading additional files for this class
        if sum(len(x) for x in class_data) >= MAX_PER_CLASS:
            break

    # Combine selected data
    if class_data:

        class_df = pd.concat(class_data, ignore_index=True)

        # Limit class size
        class_df = class_df.head(MAX_PER_CLASS)

        # Replace original labels with our clean class names
        class_df["Attack_Type"] = target_class

        all_data.append(class_df)

        print(
            f"Collected {len(class_df):,} records "
            f"for {target_class}"
        )

    else:
        print(f"WARNING: No records found for {target_class}")

# --------------------------------------------------
# COMBINE EVERYTHING
# --------------------------------------------------

print("\n" + "=" * 70)
print("COMBINING DATA")
print("=" * 70)

if not all_data:
    print("ERROR: No data was collected.")
    exit()

df = pd.concat(all_data, ignore_index=True)

# Shuffle dataset
df = df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

# --------------------------------------------------
# SAVE DATASET
# --------------------------------------------------

output_path = DATA_FOLDER / "processed_network_data.csv"

df.to_csv(
    output_path,
    index=False
)

print("\nDataset preparation complete!")

print("\nTotal records:", f"{len(df):,}")
print("Total columns:", len(df.columns))

print("\nClass distribution:")
print(df["Attack_Type"].value_counts())

print(f"\nSaved to:")
print(output_path)

print("\n" + "=" * 70)