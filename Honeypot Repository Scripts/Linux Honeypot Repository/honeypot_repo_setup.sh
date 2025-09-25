#!/bin/bash

# This is a script to set up auditd and rsyslog on a Linux Honeypot Repository to monitor specific activities
# and forward the logs to a specified SIEM server.
# The script installs necessary packages, configures auditd rules, and sets up rsyslog
# to forward logs to the SIEM server.
# Usage: sudo ./honeypot_repo_setup.sh <SIEM_SERVER> <REPO_PATH>

# 1. Check for SIEM server and repository path arguments
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <SIEM_SERVER> <REPO_PATH>"
  exit 1
fi
SIEM_SERVER="$1"
REPO_PATH="$2"

# 2. Install auditd and rsyslog
echo "[*] Installing auditd and rsyslog..."
sudo apt update
sudo apt install auditd rsyslog -y

# 3. Add audit.rules to /etc/audit/rules.d/audit.rules
echo "[*] Writing audit rules..."
sudo tee /etc/audit/rules.d/audit.rules > /dev/null << EOF
# Audit.Rules Config
# /etc/audit/rules.d/audit.rules

# Equivalent of Audit "File System"
# This rule watches for all write, attribute, and delete operations on the main repository folder.
# Any access to this specific folder is likely malicious.
-w ${REPO_PATH} -p rwxa -k veeam_repo_access

# This rule watches for any attempt to modify system binaries that an attacker might try to replace or manipulate.
-w /etc/passwd -p wa -k user_account_change
-w /etc/shadow -p wa -k user_account_change

# Equivalent of "Audit Process Creation"
# This rule will log all successful process executions.
-a always,exit -F arch=b64 -S execve -k process_creation
-a always,exit -F arch=b32 -S execve -k process_creation

# Equivalent of "Audit Handle Manipulation"
# Monitoring processes reading or writing the memory of another process.
-a always,exit -F arch=b64 -S process_vm_readv,process_vm_writev -k process_memory_access
-a always,exit -F arch=b32 -S process_vm_readv,process_vm_writev -k process_memory_access

# Monitoring ptrace system calls allowing one process to control another. 
-a always,exit -F arch=b64 -S ptrace -k process_trace
-a always,exit -F arch=b32 -S ptrace -k process_trace
EOF

# 4. Configure auditd to forward to rsyslog
echo "[*] Configuring auditd syslog plugin..."
sudo sed -i 's/^active.*/active = yes/' /etc/audit/plugins.d/syslog.conf

# 5. Apply auditd rules
echo "[*] Applying auditd rules..."
sudo augenrules --load

# 6. Make auditd rules immutable
echo "[*] Making auditd rules immutable..."
sudo auditctl -e 2

# 7. Enable and start auditd service
echo "[*] Enabling and starting auditd service..."
sudo systemctl enable auditd --now

# 8. Create rsyslog config to forward audit logs to SIEM and stop further processing
echo "[*] Creating rsyslog config for auditd forwarding..."
sudo tee /etc/rsyslog.d/auditd.conf > /dev/null << EOF
# Forward all auditd logs (LOG_LOCAL6) to SIEM and stop further processing
:programname, isequal, "audisp-syslog" @@${SIEM_SERVER}:514
authpriv.* @@${SIEM_SERVER}:514
& stop
EOF

# 9. Restart rsyslog to apply changes
echo "[*] Restarting rsyslog..."
sudo systemctl restart rsyslog

echo "[*] Setup complete. Auditd and rsyslog are configured to forward logs to $SIEM_SERVER and monitor $REPO_PATH."
