#!/usr/bin/env bash
# ==============================================================================
# CTEM Platform - Agent Verification & Attack Simulation Script
# ==============================================================================
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "$DIR"

echo "=================================================="
echo "      CTEM Agent Diagnostic & Verification        "
echo "=================================================="

# 1. Status Check
python3 agent.py status

# 2. End-to-end Test
python3 agent.py test

# 3. Port Scan
python3 agent.py scan-ports

# 4. Attack Simulation
echo ""
echo "[*] Triggering attack simulation for UEBA and Process Detection..."
python3 agent.py simulate --attack bruteforce
python3 agent.py simulate --attack webshell

echo ""
echo "[✔] Completed! Verify results on http://localhost:3000/alerts and http://localhost:3000/monitoring"
