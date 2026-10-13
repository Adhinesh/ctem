#!/usr/bin/env bash
# ==============================================================================
# CTEM Platform - Ubuntu VM Turnkey Agent Deployment Script
# ==============================================================================
# Usage:
#   sudo ./deploy_ubuntu.sh http://<CTEM_HOST_IP>:8000
#
# Examples:
#   # If host is running on LAN IP 192.168.1.50:
#   sudo ./deploy_ubuntu.sh http://192.168.1.50:8000
#
#   # If Ubuntu VM is using VirtualBox Default NAT:
#   sudo ./deploy_ubuntu.sh http://10.0.2.2:8000
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Please execute as root (use sudo):"
    echo "    sudo ./deploy_ubuntu.sh http://<CTEM_HOST_IP>:8000"
    exit 1
fi

CTEM_SERVER="${1:-http://10.0.2.2:8000}"
AGENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

echo "=========================================================="
echo "    CTEM Ubuntu Endpoint Agent Deployment & Setup        "
echo "=========================================================="
echo "[*] Target CTEM Server: $CTEM_SERVER"
echo "[*] Agent Location    : $AGENT_DIR"

# 1. Check Python3
if ! command -v python3 &> /dev/null; then
    echo "[*] Installing Python3..."
    apt-get update -y && apt-get install -y python3 python3-pip
fi

# 2. Check /var/log/auth.log access
if [ -f "/var/log/auth.log" ]; then
    echo "[+] Found Ubuntu auth log: /var/log/auth.log"
else
    echo "[!] Warning: /var/log/auth.log not found yet. Enabling rsyslog if needed..."
    apt-get install -y rsyslog
    systemctl restart rsyslog
fi

# 3. Test Connectivity to Host
echo "[*] Testing connectivity to CTEM backend ($CTEM_SERVER/health)..."
if python3 -c "import urllib.request; resp = urllib.request.urlopen('$CTEM_SERVER/health', timeout=5); print('    [+] HTTP Status:', resp.getcode())" 2>/dev/null; then
    echo "[+] SUCCESS: Host CTEM backend is reachable!"
else
    echo "[-] WARNING: Could not connect to $CTEM_SERVER/health"
    echo "    Verify that:"
    echo "    1. CTEM backend on the host is running (uvicorn app.main:app --host 0.0.0.0 --port 8000)"
    echo "    2. Host firewall allows incoming connections on port 8000"
    echo "    3. For VirtualBox NAT use: http://10.0.2.2:8000"
    echo "    4. For Bridged Adapter use the host's LAN IP: e.g. http://192.168.x.x:8000"
    read -p "Do you want to continue anyway? (y/N) " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        exit 1
    fi
fi

# 4. Save Config
cat <<EOF > "$AGENT_DIR/config.json"
{
  "server_url": "$CTEM_SERVER",
  "asset_type": "server",
  "zone": "internal",
  "criticality": "high",
  "heartbeat_interval": 30,
  "port_scan_interval": 60,
  "process_scan_interval": 30,
  "enable_logs": true,
  "enable_ueba": true,
  "enable_ports": true,
  "enable_processes": true,
  "custom_log_paths": [
    "/var/log/auth.log",
    "/var/log/syslog"
  ]
}
EOF
echo "[+] Wrote agent configuration to $AGENT_DIR/config.json"

# 5. Run Initial Diagnostics & Registration
echo "[*] Registering Ubuntu VM with CTEM Platform..."
python3 "$AGENT_DIR/agent.py" test --server "$CTEM_SERVER"

# 6. Install as a background systemd service
echo "[*] Installing systemd background service..."
SERVICE_FILE="/etc/systemd/system/ctem-agent.service"
PYTHON_BIN="$(which python3)"

cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=CTEM Continuous Asset Monitoring & Log Forwarding Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$AGENT_DIR
ExecStart=$PYTHON_BIN $AGENT_DIR/agent.py run --server $CTEM_SERVER
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ctem-agent

echo ""
echo "=========================================================="
echo " [✔] CTEM Agent is RUNNING as a systemd service on Ubuntu!"
echo "=========================================================="
echo " Service Status: sudo systemctl status ctem-agent"
echo " Live Agent Logs: sudo journalctl -u ctem-agent -f"
echo ""
echo "--- HOW TO TRIGGER REAL PREDEFINED ALERTS ---"
echo "1. Brute-Force SSH (Triggers HIGH Alert 'Repeated failed logins'):"
echo "   Run from another machine or attacker terminal:"
echo "   for i in {1..6}; do sshpass -p 'WrongPass' ssh -o StrictHostKeyChecking=no testuser@<THIS_UBUNTU_IP>; done"
echo ""
echo "2. Port Opening Drift (Triggers MEDIUM/HIGH Alert 'New port opened'):"
echo "   nc -lvnp 4444"
echo ""
echo "3. Intrusion Threat Tool (Triggers CRITICAL Alert):"
echo "   sudo nc -l 9999 &"
echo ""
echo "View alerts in real-time in the CTEM web app: http://localhost:3000/alerts"
