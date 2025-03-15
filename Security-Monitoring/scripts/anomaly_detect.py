import pandas as pd
import time
import os
import numpy as np
from sklearn.ensemble import IsolationForest
from scipy.stats import zscore
from tabulate import tabulate

# File paths
structured_logs_file = "../logs/structured_logs.csv"
anomalous_logs_file = "../logs/anomalous_logs.csv"

def load_logs():
    """Loads structured logs from CSV and ensures proper data types."""
    try:
        df = pd.read_csv(structured_logs_file)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except FileNotFoundError:
        return pd.DataFrame()

def detect_anomalies(df):
    """Applies anomaly detection using Z-score and Isolation Forest."""
    if df.empty:
        return df  # Return empty DataFrame if no logs

    # Compute Z-score to detect outliers in request size
    df["size_zscore"] = zscore(df["size"])
    
    # Flag high Z-score values as anomalies (|Z| > 3)
    df["size_anomaly"] = df["size_zscore"].abs() > 3

    # Apply Isolation Forest for behavior-based anomaly detection
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    df["request_length"] = df["request"].apply(len)  # Feature: Request length
    df["status_code"] = df["status"].astype(int)  # Convert status to int
    df["iso_forest"] = model.fit_predict(df[["request_length", "status_code", "size"]]) == -1  # Anomaly if -1

    # Final anomaly detection column
    df["is_anomaly"] = df["size_anomaly"] | df["iso_forest"]

    return df[df["is_anomaly"] == True]  # Return only anomalies

def display_table(df, title):
    """Displays detected anomalies in a structured table format."""
    if df.empty:
        print(f"\n📂 {title}\nNo anomalies detected.")
        return

    table_headers = ["IP Address", "Timestamp", "Request", "Status", "Size"]
    table_data = df[["ip", "timestamp", "request", "status", "size"]].values.tolist()

    print(f"\n📂 {title}")
    print(tabulate(table_data, headers=table_headers, tablefmt="grid"))

# Continuously monitor logs for anomalies
while True:
    os.system("clear")

    logs_df = load_logs()
    anomalous_logs = detect_anomalies(logs_df)

    # Save anomalies to CSV for later analysis
    if not anomalous_logs.empty:
        anomalous_logs.to_csv(anomalous_logs_file, index=False)

    display_table(anomalous_logs, "⚠️ Detected Anomalous Activity")

    time.sleep(5)  # Refresh every 5 seconds

