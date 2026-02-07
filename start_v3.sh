#!/bin/bash
# MedyDorker v3.0 — Start Script
# Usage: ./start_v3.sh

cd "$(dirname "$0")"

echo "=== MedyDorker v3.0 ==="
echo "Installing dependencies..."
pip install -r requirements_v3.txt -q 2>/dev/null

echo "Starting bot..."
python main_v3.py
