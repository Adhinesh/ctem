#!/usr/bin/env bash
# ==============================================================================
# CTEM Platform - Agent System Service Installer
# ==============================================================================
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
PYTHON_BIN="$(which python3)"

echo "[*] CTEM Agent Directory: $DIR"
echo "[*] Python Executable: $PYTHON_BIN"

if [ "$(uname)" == "Darwin" ]; then
    PLIST_PATH="$HOME/Library/LaunchAgents/com.ctem.agent.plist"
    echo "[*] Installing macOS LaunchAgent: $PLIST_PATH"
    mkdir -p "$HOME/Library/LaunchAgents"

    cat <<EOF > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ctem.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_BIN</string>
        <string>$DIR/agent.py</string>
        <string>run</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/ctem-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/ctem-agent.err</string>
</dict>
</plist>
EOF
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
    launchctl load -w "$PLIST_PATH"
    echo "[+] CTEM Agent LaunchAgent loaded successfully!"
    echo "    Check logs at /tmp/ctem-agent.log"

elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    if [ "$EUID" -ne 0 ]; then
        echo "[-] Please run as root (sudo ./install_service.sh) to install systemd unit."
        exit 1
    fi

    SERVICE_FILE="/etc/systemd/system/ctem-agent.service"
    echo "[*] Installing Linux systemd service: $SERVICE_FILE"

    cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=CTEM Continuous Asset Monitoring & Log Forwarding Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$DIR
ExecStart=$PYTHON_BIN $DIR/agent.py run
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
    systemctl status ctem-agent --no-pager
    echo "[+] CTEM Agent systemd service installed and started!"
fi
