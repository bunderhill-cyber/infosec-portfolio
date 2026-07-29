#!/usr/bin/env python3
"""
behavioral_anomaly_detector.py
Simple Behavioral Analytics (UEBA-lite) for Insider Threat Detection

Compares recent activity against per-user baselines and produces a scored report.
Baselines are maintained manually in user_baselines.csv.

Author: B. Underhill Cybersecurity Portfolio
Version: 1.1
"""

import pandas as pd
import glob
import os
from datetime import datetime

# ====================== CONFIGURATION ======================
LOGON_REPORT_PATTERN = "LogonAnomalyReport_*.csv"
USB_REPORT_PATTERN   = "USBExfilReport_*.csv"
BASELINE_FILE        = "user_baselines.csv"
OUTPUT_REPORT        = f"BehavioralAnomalyReport_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"

# How many standard deviations away from the mean is considered anomalous
ZSCORE_THRESHOLD = 2.0

# System / noise accounts to ignore
IGNORE_USERS = [
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
    "DWM-0", "DWM-1", "DWM-2", "UMFD-0", "UMFD-1", "UMFD-2", "Unknown"
]
# ===========================================================


def find_latest_file(pattern: str) -> str | None:
    """Return the most recent file matching the pattern, or None."""
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def load_baselines(path: str) -> pd.DataFrame:
    """Load the user baselines CSV."""
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Baseline file '{path}' not found. Create it first with the required columns."
        )
    return pd.read_csv(path)


def load_recent_activity() -> pd.DataFrame:
    """
    Load and combine the latest logon and USB reports.
    Returns a simplified activity DataFrame with one row per user.
    """
    activity = {}

    # --- Logon data ---
    logon_file = find_latest_file(LOGON_REPORT_PATTERN)
    if logon_file:
        print(f"[+] Using logon report: {logon_file}")
        logon_df = pd.read_csv(logon_file)

        # Robust datetime parsing
        logon_df["Timestamp"] = pd.to_datetime(logon_df["Timestamp"], errors="coerce", format="mixed")

        for user, group in logon_df.groupby("User"):
            if user in IGNORE_USERS:
                continue
            activity.setdefault(user, {})
            hours = group["Timestamp"].dt.hour.dropna()
            if not hours.empty:
                activity[user]["RecentAvgLogonHour"] = hours.mean()
            activity[user]["RecentFailedLogons"] = (group["EventID"] == 4625).sum()

    # --- USB data ---
    usb_file = find_latest_file(USB_REPORT_PATTERN)
    if usb_file:
        print(f"[+] Using USB report: {usb_file}")
        usb_df = pd.read_csv(usb_file)

        # Handle missing User column
        if "User" not in usb_df.columns:
            print("[!] USB report has no 'User' column – assigning activity to 'Unknown'")
            usb_df["User"] = "Unknown"

        for user, group in usb_df.groupby("User"):
            if user in IGNORE_USERS:
                continue
            activity.setdefault(user, {})
            activity[user]["RecentUSBWriteMB"] = group["SizeMB"].sum()

    # Convert to DataFrame
    records = []
    for user, metrics in activity.items():
        records.append({
            "User": user,
            "RecentAvgLogonHour": metrics.get("RecentAvgLogonHour"),
            "RecentFailedLogons": metrics.get("RecentFailedLogons", 0),
            "RecentUSBWriteMB": metrics.get("RecentUSBWriteMB", 0.0)
        })
    return pd.DataFrame(records)


def calculate_zscore(value, mean, std):
    """Simple z-score. Returns 0 if std is zero or value is missing."""
    if pd.isna(value) or pd.isna(mean) or std == 0 or pd.isna(std):
        return 0.0
    return (value - mean) / std


def score_anomalies(activity_df: pd.DataFrame, baselines: pd.DataFrame) -> pd.DataFrame:
    """Compare recent activity against baselines and produce scores."""
    results = []

    for _, row in activity_df.iterrows():
        user = row["User"]
        baseline = baselines[baselines["User"] == user]

        if baseline.empty:
            results.append({
                "User": user,
                "AnomalyScore": 0.0,
                "Reasons": "No baseline available",
                "RecentAvgLogonHour": row.get("RecentAvgLogonHour"),
                "RecentFailedLogons": row.get("RecentFailedLogons"),
                "RecentUSBWriteMB": row.get("RecentUSBWriteMB")
            })
            continue

        b = baseline.iloc[0]
        reasons = []
        score = 0.0

        # Logon hour deviation
        z_hour = calculate_zscore(row["RecentAvgLogonHour"], b["AvgLogonHour"], b["StdLogonHour"])
        if abs(z_hour) >= ZSCORE_THRESHOLD:
            reasons.append(f"Unusual logon hour (z={z_hour:.1f})")
            score += abs(z_hour)

        # Failed logons deviation
        z_failed = calculate_zscore(row["RecentFailedLogons"], b["AvgFailedLogons"], b["StdFailedLogons"])
        if abs(z_failed) >= ZSCORE_THRESHOLD:
            reasons.append(f"Elevated failed logons (z={z_failed:.1f})")
            score += abs(z_failed)

        # USB volume deviation
        z_usb = calculate_zscore(row["RecentUSBWriteMB"], b["AvgUSBWriteMB"], b["StdUSBWriteMB"])
        if abs(z_usb) >= ZSCORE_THRESHOLD:
            reasons.append(f"Unusual USB write volume (z={z_usb:.1f})")
            score += abs(z_usb)

        results.append({
            "User": user,
            "AnomalyScore": round(score, 2),
            "Reasons": "; ".join(reasons) if reasons else "Within normal baseline",
            "RecentAvgLogonHour": row.get("RecentAvgLogonHour"),
            "RecentFailedLogons": row.get("RecentFailedLogons"),
            "RecentUSBWriteMB": row.get("RecentUSBWriteMB")
        })

    return pd.DataFrame(results).sort_values("AnomalyScore", ascending=False)


def main():
    print("[*] Starting Behavioral Anomaly Detection (v1.1)...")

    try:
        baselines = load_baselines(BASELINE_FILE)
        print(f"[+] Loaded baselines for {len(baselines)} users")
    except FileNotFoundError as e:
        print(f"[!] {e}")
        return

    activity = load_recent_activity()
    if activity.empty:
        print("[!] No recent activity reports found. Run the PowerShell scripts first.")
        return
    print(f"[+] Loaded recent activity for {len(activity)} users")

    report = score_anomalies(activity, baselines)

    report.to_csv(OUTPUT_REPORT, index=False)
    print(f"\n[+] Report saved: {OUTPUT_REPORT}")
    print("\n=== Behavioral Anomaly Summary ===")
    print(report.to_string(index=False))


if __name__ == "__main__":
    main()