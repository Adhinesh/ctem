import os
import sys
import platform
import logging

logger = logging.getLogger("ctem_agent.service")

SYSTEMD_TEMPLATE = """[Unit]
Description=CTEM Continuous Asset Monitoring & Log Forwarding Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={working_dir}
ExecStart={python_path} {agent_py} run
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""

LAUNCHD_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ctem.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_path}</string>
        <string>{agent_py}</string>
        <string>run</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{working_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/ctem-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/ctem-agent.err</string>
</dict>
</plist>
"""


def generate_service_definition(working_dir: str, agent_py: str, python_path: str = sys.executable) -> str:
    """Generates the appropriate system daemon service specification for current OS."""
    os_name = platform.system()
    if os_name == "Darwin":
        return LAUNCHD_TEMPLATE.format(
            python_path=python_path,
            agent_py=agent_py,
            working_dir=working_dir,
        )
    else:
        return SYSTEMD_TEMPLATE.format(
            python_path=python_path,
            agent_py=agent_py,
            working_dir=working_dir,
        )


def install_service(agent_dir: str) -> bool:
    """Installs the service configuration into the system daemon directory."""
    os_name = platform.system()
    agent_py = os.path.join(agent_dir, "agent.py")
    python_path = sys.executable

    content = generate_service_definition(agent_dir, agent_py, python_path)

    if os_name == "Linux":
        service_path = "/etc/systemd/system/ctem-agent.service"
        try:
            with open(service_path, "w") as f:
                f.write(content)
            print(f"[+] Installed systemd unit to: {service_path}")
            print("[+] To enable and start the agent service, run:")
            print("    sudo systemctl daemon-reload")
            print("    sudo systemctl enable --now ctem-agent")
            print("    sudo systemctl status ctem-agent")
            return True
        except PermissionError:
            print("[-] Error: Root privileges required. Run with sudo: sudo python3 agent.py install-service")
            local_fallback = os.path.join(agent_dir, "scripts", "ctem-agent.service")
            with open(local_fallback, "w") as f:
                f.write(content)
            print(f"[*] Generated service template locally at: {local_fallback}")
            return False
    elif os_name == "Darwin":
        plist_path = os.path.expanduser("~/Library/LaunchAgents/com.ctem.agent.plist")
        try:
            os.makedirs(os.path.dirname(plist_path), exist_ok=True)
            with open(plist_path, "w") as f:
                f.write(content)
            print(f"[+] Installed launchd plist to: {plist_path}")
            print("[+] To load and start the agent service, run:")
            print(f"    launchctl load -w {plist_path}")
            return True
        except Exception as e:
            print(f"[-] Failed to write plist: {e}")
            return False
    else:
        print("[!] Windows service install: Please use NSSM or Task Scheduler to run:")
        print(f"    {python_path} {agent_py} run")
        return False
