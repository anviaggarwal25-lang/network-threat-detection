import pandas as pd
from pathlib import Path

# Location of our dataset
DATA_FOLDER = Path("data/MachineLearningCVE")

# We'll start with the Monday dataset
file_path = DATA_FOLDER / "Monday-WorkingHours.pcap_ISCX.csv"

print("=" * 60)
print("NETWORK THREAT DETECTION - DATASET INSPECTION")
print("=" * 60)

print("\nLoading dataset...")

# Load only 10,000 rows for our first inspection
df = pd.read_csv(file_path, nrows=10000)

print("\nDataset loaded successfully!")

print("\nNumber of rows loaded:", len(df))
print("Number of columns:", len(df.columns))

print("\n" + "=" * 60)
print("COLUMN NAMES")
print("=" * 60)

for i, column in enumerate(df.columns, start=1):
    print(f"{i}. {column}")

print("\n" + "=" * 60)
print("LABEL DISTRIBUTION")
print("=" * 60)

# Remove accidental spaces from column names
df.columns = df.columns.str.strip()

print(df["Label"].value_counts())

print("\n" + "=" * 60)
print("MISSING VALUES")
print("=" * 60)

missing = df.isnull().sum()

print(missing[missing > 0])

print("\n" + "=" * 60)
print("FIRST 5 RECORDS")
print("=" * 60)

print(df.head())