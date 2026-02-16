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
- Main panel pages: Dashboard, Services, Files, Movies, Terminal, Network, Packages, Scheduler, Logs, Changelog
- Auth model: session-based login with password loaded from `PANEL_PASSWORD` or generated in `~/.mini-control-password`

## Features

- **Dashboard** - Live auto-refreshing CPU, RAM, disk, temperature, uptime, load average, service status
- **Monitoring Charts** - Last-hour CPU, RAM, disk I/O, and network bandwidth history (in-memory, lightweight)
- **Service Manager** - List, start, stop, restart systemd services, view logs
- **File Manager** - Browse, upload, download, delete, and create files/folders
- **Movies** - Local movie browser with drag/drop uploads, OMDb metadata lookup/cache, streaming, and delete controls
- **System Terminal** - Execute commands with shortcut buttons, persistent history, copy/clear output
- **Network Info** - IP, MAC, gateway, DNS, ping tests, active connections
- **Package Manager** - Search, install, remove apt packages
- **Scheduler** - Manage user cron jobs (add, edit, delete, quick presets, next run time)
- **Logs Viewer** - journalctl, dmesg, syslog with filtering, auto-refresh, and log downloads
- **Power Management** - Reboot, shutdown, schedule reboot, and cancel scheduled shutdown
- **Changelog** - Full git commit history + local `CHANGELOG.md` release notes

## Requirements

- Debian 12 (i386) with Python 3.11
- 2GB RAM (panel uses ~20-30MB)
- SSH access
- Optional for Movies tab: an [OMDb API key](https://www.omdbapi.com/apikey.aspx) stored in `~/.mini-control-omdb-key`

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

Password source:

- `PANEL_PASSWORD` environment variable (if set), or
- auto-generated file: `~/.mini-control-password`

Show current password on the server:

```bash
cat /home/ludovic/.mini-control-password
```

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

Environment variables:

- `PANEL_PASSWORD` - Login password override
- `SECRET_KEY` - Flask session secret override
- `PANEL_HOST` - Bind host (default: `0.0.0.0`)
- `PANEL_PORT` - Bind port (default: `5000`)
- `FILE_ROOT` - Root directory for file manager (default: `/home/ludovic`)
- `PANEL_ALLOWED_SUBNETS` - Comma-separated CIDR allowlist (default private LAN ranges)
- `ENABLE_WEB_TERMINAL` - `true/false` (default `false`)
- `ENABLE_ASSISTANT_EXEC` - `true/false` (default `false`)
- `ENABLE_ASSISTANT_FILE_EDITOR` - `true/false` (default `false`)

## Security Notes

- The panel runs as user `ludovic`, not root
- Login password and Flask secret are generated automatically if not provided
- Access is restricted to private/loopback subnets by default
- CSRF protection is enabled for state-changing requests
- Sudo permissions are limited to systemctl and apt-get operations
- Assistant file read/write does not use sudo and is restricted to `FILE_ROOT`
- Web terminal, assistant command execution, and assistant file editor are disabled by default (opt-in via env vars)
- File manager is restricted to `/home/ludovic`
- For Power actions, add sudoers rules:
  - `ludovic ALL=(ALL) NOPASSWD: /sbin/reboot`
  - `ludovic ALL=(ALL) NOPASSWD: /sbin/shutdown *`
- Consider using a reverse proxy with HTTPS for production use
