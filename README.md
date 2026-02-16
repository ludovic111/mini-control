# Mini Control - Mac Mini Server Panel

A lightweight web control panel for managing a Mac Mini server running Debian 12 (i386).

## Current Machine Context

- Model: Mac Mini Mid-2006
- CPU: Intel Core Duo T2300
- Architecture: 32-bit ONLY (`i686/i386`)
- RAM: 2GB
- OS: Debian 12 Bookworm (`i386`)
- User: `ludovic`
- Server IP: `192.168.1.50`
- Main panel pages: Dashboard, Services, Files, Terminal, Network, Packages, Logs, Changelog
- Auth model: session-based login with password stored in `config.py` (`PASSWORD`)

## Features

- **Dashboard** - CPU, RAM, disk usage, uptime, temperature, load average, service status
- **Service Manager** - List, start, stop, restart systemd services, view logs
- **File Manager** - Browse, upload, download, delete, and create files/folders
- **System Terminal** - Execute commands with shortcut buttons, persistent history, copy/clear output
- **Network Info** - IP, MAC, gateway, DNS, ping tests, active connections
- **Package Manager** - Search, install, remove apt packages
- **Logs Viewer** - journalctl, dmesg, syslog with filtering, auto-refresh, and log downloads
- **Changelog** - Full git commit history + local `CHANGELOG.md` release notes

## Requirements

- Debian 12 (i386) with Python 3.11
- 2GB RAM (panel uses ~20-30MB)
- SSH access

## Installation

### 1. Transfer to Mac Mini

```bash
scp -r mini-control ludovic@192.168.1.50:~/
```

### 2. Run setup

```bash
ssh ludovic@192.168.1.50 "cd ~/mini-control && chmod +x setup.sh && ./setup.sh"
```

### 3. Access the panel

Open in your browser:

```
http://192.168.1.50:5000
```

## Updating the Panel via SSH

From your local machine, sync your latest changes:

```bash
cd "/Users/ludovicmarie/Desktop/FOLDERS/CODING PROJECTS/minilinux"
rsync -avz --delete mini-control/ ludovic@192.168.1.50:~/mini-control/
```

Then restart the service on the server:

```bash
ssh ludovic@192.168.1.50 "sudo systemctl restart mini-control && sudo systemctl status mini-control --no-pager -l"
```

### 4. Login

Default password: `minilinux2006`

Change it in `config.py` or set the `PANEL_PASSWORD` environment variable.

## Managing the Service

```bash
# Check status
sudo systemctl status mini-control

# Restart
sudo systemctl restart mini-control

# Stop
sudo systemctl stop mini-control

# View logs
journalctl -u mini-control -f
```

## Configuration

Edit `config.py` to change:

- `PASSWORD` - Login password
- `SECRET_KEY` - Flask session secret
- `PORT` - Web server port (default: 5000)
- `FILE_ROOT` - Root directory for file manager

## Security Notes

- Change the default password immediately after setup
- The panel runs as user `ludovic`, not root
- Sudo permissions are limited to systemctl and apt-get operations
- File manager is restricted to `/home/ludovic`
- Consider using a reverse proxy with HTTPS for production use
