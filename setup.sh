#!/bin/bash
set -e

echo "=== Mac Mini Control Panel - Setup ==="
echo ""

# Install system dependencies
echo "[1/5] Installing system dependencies..."
sudo apt update -qq
sudo apt install -y python3-pip

# Install pip packages
echo "[2/5] Installing Python packages..."
pip install flask psutil requests --break-system-packages

# Copy systemd service file
echo "[3/5] Installing systemd service..."
sudo cp mini-control.service /etc/systemd/system/mini-control.service
sudo systemctl daemon-reload

# Enable and start the service
echo "[4/5] Enabling and starting the service..."
sudo systemctl enable mini-control.service
sudo systemctl start mini-control.service

# Configure sudoers for service management (no password for systemctl, apt, power actions)
echo "[5/5] Configuring sudo permissions for panel..."
SUDOERS_FILE="/etc/sudoers.d/mini-control"
if [ ! -f "$SUDOERS_FILE" ]; then
    sudo tee "$SUDOERS_FILE" > /dev/null << 'SUDOERS'
ludovic ALL=(ALL) NOPASSWD: /usr/bin/systemctl start *
ludovic ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop *
ludovic ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart *
ludovic ALL=(ALL) NOPASSWD: /usr/bin/apt-get install *
ludovic ALL=(ALL) NOPASSWD: /usr/bin/apt-get remove *
ludovic ALL=(ALL) NOPASSWD: /usr/bin/tee *
ludovic ALL=(ALL) NOPASSWD: /usr/bin/cat *
ludovic ALL=(ALL) NOPASSWD: /sbin/reboot
ludovic ALL=(ALL) NOPASSWD: /sbin/shutdown *
SUDOERS
    sudo chmod 0440 "$SUDOERS_FILE"
    echo "  Sudoers file created at $SUDOERS_FILE"
else
    echo "  Sudoers file already exists, skipping"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
IP=$(hostname -I | awk '{print $1}')
echo "Control Panel URL: http://${IP}:5000"
echo "Default password:  minilinux2006"
echo ""
echo "Service status:"
sudo systemctl status mini-control.service --no-pager -l
