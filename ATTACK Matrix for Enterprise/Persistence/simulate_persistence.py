#!/usr/bin/env python3
"""
simulate_persistence.py - Demonstrates MITRE ATT&CK T1053.005 (Scheduled Task)

EDUCATIONAL PURPOSES ONLY. For authorized penetration testing and lab environments.
Never use on unauthorized systems. Running this on production or third-party systems
without explicit permission is illegal.

This script creates a benign scheduled task for demonstration. Pair it with
Hunt-PersistenceMechanisms.ps1 to practice detection.
"""

import argparse
import logging
import os
import random
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("persistence.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

TASK_NAME = "SecurityScanDemo"  # Configurable, avoid real security-sounding names in prod labs

def run_command(cmd: list) -> subprocess.CompletedProcess:
    """Run a command safely and return result."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            logger.warning(f"Command failed: {' '.join(cmd)}\n{result.stderr}")
        return result
    except Exception as e:
        logger.error(f"Error running command: {e}")
        return None

def enumerate_tasks():
    """List scheduled tasks (useful for defensive validation)."""
    logger.info("Enumerating scheduled tasks...")
    result = run_command(["schtasks", "/query", "/tn", TASK_NAME])
    if result and result.returncode == 0:
        print(result.stdout)
    else:
        print(f"No task named '{TASK_NAME}' found or error occurred.")

def delete_task():
    """Delete the demo task if it exists."""
    logger.info(f"Attempting to delete task: {TASK_NAME}")
    result = run_command(["schtasks", "/delete", "/f", "/tn", TASK_NAME])
    if result and result.returncode == 0:
        logger.info("Task deleted successfully.")
    else:
        logger.warning("Task may not exist or deletion failed.")

def create_task(target_script: str, delay_minutes: int = 5):
    """Create a scheduled task that runs the target script once after a delay."""
    if not Path(target_script).exists():
        logger.error(f"Target script not found: {target_script}")
        return False

    now = datetime.now()
    future = now + timedelta(minutes=delay_minutes)
    start_time = future.strftime("%H:%M")
    start_date = future.strftime("%m/%d/%Y")

    logger.info(f"Creating task '{TASK_NAME}' to run {target_script} at {start_time} on {start_date}")

    cmd = [
        "schtasks", "/create",
        "/tn", TASK_NAME,
        "/tr", f'"{target_script}"',  # Quote the path
        "/sc", "once",
        "/st", start_time,
        "/sd", start_date,
        "/ru", "SYSTEM",  # Or current user; SYSTEM for higher privileges in lab
        "/f"              # Force
    ]

    result = run_command(cmd)
    if result and result.returncode == 0:
        logger.info("Task created successfully.")
        print(f"Task '{TASK_NAME}' scheduled. Use your PowerShell hunter to detect it.")
        return True
    return False

def main():
    parser = argparse.ArgumentParser(description="Simulate Scheduled Task Persistence (T1053.005)")
    parser.add_argument("--action", choices=["add", "delete", "enumerate"], default="enumerate",
                        help="Action to perform")
    parser.add_argument("--script", type=str, default=__file__,
                        help="Script to schedule (default: this script)")
    parser.add_argument("--delay", type=int, default=5,
                        help="Delay in minutes before task runs (default: 5)")
    args = parser.parse_args()

    print("=== Scheduled Task Persistence Demo (Lab Use Only) ===")
    
    if args.action == "enumerate":
        enumerate_tasks()
    elif args.action == "delete":
        delete_task()
    elif args.action == "add":
        # Optional: make payload more obvious for detection practice
        print("Creating demo task (benign payload)...")
        create_task(args.script, args.delay)

if __name__ == "__main__":
    if os.name != "nt":
        print("This script is designed for Windows.")
        sys.exit(1)
    main()