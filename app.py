#!/usr/bin/env python3
"""Mac Mini Control Panel - Flask Web Application"""

import base64
import hashlib
import json
import os
import secrets
import shlex
import signal
import subprocess
import time
import urllib.parse
from datetime import datetime
from functools import wraps
from pathlib import Path

import psutil
import requests as http_requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, send_file, flash, abort
)

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY


# --- Auth decorator ---

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# --- Helper functions ---

def run_cmd(cmd, timeout=30, shell=True):
    """Run a shell command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return '', 'Command timed out', 1
    except Exception as e:
        return '', str(e), 1


def safe_path(requested_path):
    """Resolve path and ensure it stays within FILE_ROOT."""
    root = Path(config.FILE_ROOT).resolve()
    target = (root / requested_path).resolve()
    if not str(target).startswith(str(root)):
        return None
    return target


def format_bytes(n):
    """Format bytes to human readable string."""
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def get_cpu_temp():
    """Get CPU temperature via psutil or thermal zone."""
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            for name in ('coretemp', 'cpu_thermal', 'cpu-thermal', 'acpitz'):
                if name in temps and temps[name]:
                    return f"{temps[name][0].current:.1f}"
        # Fallback: read thermal zone
        thermal_path = '/sys/class/thermal/thermal_zone0/temp'
        if os.path.exists(thermal_path):
            with open(thermal_path) as f:
                return f"{int(f.read().strip()) / 1000:.1f}"
    except Exception:
        pass
    return 'N/A'


def check_service(name):
    """Check if a systemd service is active."""
    _, _, rc = run_cmd(f'systemctl is-active {shlex.quote(name)}')
    return rc == 0


# --- Auth routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == config.PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        flash('Invalid password', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# --- Dashboard ---

@app.route('/')
@login_required
def dashboard():
    cpu_percent = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime_delta = datetime.now() - boot_time
    days = uptime_delta.days
    hours, remainder = divmod(uptime_delta.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    uptime_str = f"{days}d {hours}h {minutes}m"
    load_avg = os.getloadavg()

    return render_template('dashboard.html',
        cpu_percent=cpu_percent,
        mem_total=format_bytes(mem.total),
        mem_used=format_bytes(mem.used),
        mem_percent=mem.percent,
        disk_total=format_bytes(disk.total),
        disk_used=format_bytes(disk.used),
        disk_percent=disk.percent,
        uptime=uptime_str,
        cpu_temp=get_cpu_temp(),
        load_avg=f"{load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}",
        ssh_active=check_service('ssh'),
        panel_active=check_service('mini-control'),
    )


@app.route('/api/dashboard')
@login_required
def api_dashboard():
    cpu_percent = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime_delta = datetime.now() - boot_time
    days = uptime_delta.days
    hours, remainder = divmod(uptime_delta.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    load_avg = os.getloadavg()

    return jsonify({
        'cpu_percent': cpu_percent,
        'mem_used': format_bytes(mem.used),
        'mem_total': format_bytes(mem.total),
        'mem_percent': mem.percent,
        'disk_used': format_bytes(disk.used),
        'disk_total': format_bytes(disk.total),
        'disk_percent': disk.percent,
        'uptime': f"{days}d {hours}h {minutes}m",
        'cpu_temp': get_cpu_temp(),
        'load_avg': f"{load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}",
        'ssh_active': check_service('ssh'),
        'panel_active': check_service('mini-control'),
    })


# --- Service Manager ---

@app.route('/services')
@login_required
def services():
    stdout, _, _ = run_cmd(
        "systemctl list-units --type=service --all --no-pager --no-legend "
        "| awk '{print $1, $2, $3, $4}'",
        timeout=10
    )
    service_list = []
    for line in stdout.splitlines():
        parts = line.split(None, 3)
        if len(parts) >= 4:
            service_list.append({
                'name': parts[0],
                'load': parts[1],
                'active': parts[2],
                'sub': parts[3],
            })
    return render_template('services.html', services=service_list)


@app.route('/api/service/<action>/<name>', methods=['POST'])
@login_required
def service_action(action, name):
    if action not in ('start', 'stop', 'restart'):
        return jsonify({'error': 'Invalid action'}), 400
    safe_name = shlex.quote(name)
    stdout, stderr, rc = run_cmd(f'sudo systemctl {action} {safe_name}', timeout=15)
    if rc != 0:
        return jsonify({'error': stderr or 'Command failed'}), 500
    return jsonify({'status': 'ok', 'message': f'{name} {action}ed successfully'})


@app.route('/api/service/logs/<name>')
@login_required
def service_logs(name):
    safe_name = shlex.quote(name)
    stdout, stderr, rc = run_cmd(
        f'journalctl -u {safe_name} -n 50 --no-pager', timeout=10
    )
    return jsonify({'logs': stdout or stderr or 'No logs available'})


# --- File Manager ---

@app.route('/files')
@app.route('/files/<path:subpath>')
@login_required
def files(subpath=''):
    target = safe_path(subpath)
    if target is None:
        abort(403)
    if not target.exists():
        abort(404)
    if not target.is_dir():
        abort(400)

    items = []
    try:
        for entry in sorted(target.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
            try:
                stat = entry.stat()
                items.append({
                    'name': entry.name,
                    'is_dir': entry.is_dir(),
                    'size': format_bytes(stat.st_size) if not entry.is_dir() else '-',
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                    'path': str(entry.relative_to(Path(config.FILE_ROOT).resolve())),
                })
            except PermissionError:
                items.append({
                    'name': entry.name,
                    'is_dir': entry.is_dir(),
                    'size': '-',
                    'modified': '-',
                    'path': str(entry.relative_to(Path(config.FILE_ROOT).resolve())),
                })
    except PermissionError:
        flash('Permission denied', 'error')

    parent = None
    rel = Path(subpath)
    if str(rel) != '.':
        parent = str(rel.parent) if str(rel.parent) != '.' else ''

    return render_template('files.html',
        items=items, current_path=subpath, parent=parent)


@app.route('/files/download/<path:subpath>')
@login_required
def download_file(subpath):
    target = safe_path(subpath)
    if target is None:
        abort(403)
    if not target.exists() or not target.is_file():
        abort(404)
    return send_file(str(target), as_attachment=True)


@app.route('/files/delete/<path:subpath>', methods=['POST'])
@login_required
def delete_file(subpath):
    target = safe_path(subpath)
    if target is None:
        return jsonify({'error': 'Access denied'}), 403
    if not target.exists():
        return jsonify({'error': 'Not found'}), 404
    try:
        if target.is_dir():
            import shutil
            shutil.rmtree(str(target))
        else:
            target.unlink()
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/files/upload/<path:subpath>', methods=['POST'])
@login_required
def upload_file(subpath=''):
    target_dir = safe_path(subpath)
    if target_dir is None:
        return jsonify({'error': 'Access denied'}), 403
    if not target_dir.is_dir():
        return jsonify({'error': 'Not a directory'}), 400

    uploaded = request.files.get('file')
    if not uploaded or uploaded.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    filename = Path(uploaded.filename).name  # strip any path components
    dest = target_dir / filename
    try:
        uploaded.save(str(dest))
        return jsonify({'status': 'ok', 'filename': filename})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/files/upload', methods=['POST'])
@login_required
def upload_file_root():
    return upload_file('')


# --- System Terminal ---

@app.route('/terminal')
@login_required
def terminal():
    return render_template('terminal.html')


@app.route('/api/terminal', methods=['POST'])
@login_required
def api_terminal():
    cmd = request.json.get('command', '').strip()
    if not cmd:
        return jsonify({'error': 'Empty command'}), 400
    stdout, stderr, rc = run_cmd(cmd, timeout=30)
    output = stdout
    if stderr:
        output = output + '\n' + stderr if output else stderr
    return jsonify({'output': output or '(no output)', 'returncode': rc})


# --- AI Assistant ---

API_KEY_FILE = os.path.expanduser('~/.mini-control-api-key')
OAUTH_TOKEN_FILE = os.path.expanduser('~/.mini-control-oauth-token')
ASSISTANT_SYSTEM_PROMPT = (
    "You are an AI assistant managing a Mac Mini server running Debian 12 i386. "
    "The machine has 2GB RAM, a 32-bit Intel Core Duo T2300 CPU, and 500GB HDD. "
    "Help the user manage, troubleshoot, and configure this server. "
    "When suggesting commands, wrap them in ```bash code blocks so the user can "
    "execute them directly. Be concise. Remember this is a 32-bit system so many "
    "modern packages won't work. "
    "You can also edit files on this server. When suggesting file edits, use "
    "```filepath:/path/to/file code blocks to let the user open the file in the "
    "built-in editor. For example: ```filepath:/etc/hostname"
)

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB max for editor


def load_api_key():
    """Load Anthropic API key from file."""
    try:
        if os.path.exists(API_KEY_FILE):
            with open(API_KEY_FILE, 'r') as f:
                return f.read().strip()
    except Exception:
        pass
    return ''


def load_oauth_token():
    """Load OAuth access token from file."""
    try:
        if os.path.exists(OAUTH_TOKEN_FILE):
            with open(OAUTH_TOKEN_FILE, 'r') as f:
                data = json.load(f)
                return data.get('access_token', ''), data.get('refresh_token', '')
    except Exception:
        pass
    return '', ''


def save_oauth_token(access_token, refresh_token=''):
    """Save OAuth tokens to file."""
    try:
        data = {'access_token': access_token, 'refresh_token': refresh_token}
        with open(OAUTH_TOKEN_FILE, 'w') as f:
            json.dump(data, f)
        os.chmod(OAUTH_TOKEN_FILE, 0o600)
        return True
    except Exception:
        return False


def get_auth_method():
    """Determine which auth method is available: 'oauth', 'apikey', or None."""
    oauth_token, _ = load_oauth_token()
    if oauth_token:
        return 'oauth'
    api_key = load_api_key()
    if api_key:
        return 'apikey'
    return None


def generate_pkce():
    """Generate PKCE code verifier and challenge for OAuth."""
    verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return verifier, challenge


def get_system_context():
    """Build current system context string for Claude."""
    try:
        hostname, _, _ = run_cmd('hostname', timeout=5)
        cpu_percent = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        load_avg = os.getloadavg()
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_delta = datetime.now() - boot_time
        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        temp = get_cpu_temp()

        services_out, _, _ = run_cmd(
            "systemctl list-units --type=service --state=running --no-pager --no-legend "
            "| awk '{print $1}' | head -20",
            timeout=5
        )

        ctx = (
            f"[Current System Status]\n"
            f"Hostname: {hostname}\n"
            f"OS: Debian 12 Bookworm i386 (32-bit)\n"
            f"CPU: Intel Core Duo T2300 @ {cpu_percent}% usage\n"
            f"CPU Temp: {temp}C\n"
            f"RAM: {format_bytes(mem.used)} / {format_bytes(mem.total)} ({mem.percent}%)\n"
            f"Disk: {format_bytes(disk.used)} / {format_bytes(disk.total)} ({disk.percent}%)\n"
            f"Load Average: {load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}\n"
            f"Uptime: {days}d {hours}h {minutes}m\n"
            f"Running services:\n{services_out}\n"
        )
        return ctx
    except Exception as e:
        return f"[System info unavailable: {e}]"


def call_anthropic_api(model, messages):
    """Call Anthropic Messages API. Tries OAuth Bearer token first, then API key."""
    url = 'https://api.anthropic.com/v1/messages'
    headers = {
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01',
    }

    # Determine auth: OAuth token takes priority
    oauth_token, refresh_token = load_oauth_token()
    if oauth_token:
        headers['Authorization'] = f'Bearer {oauth_token}'
    else:
        api_key = load_api_key()
        if not api_key:
            return None, 'No API key or OAuth token configured.'
        headers['x-api-key'] = api_key

    system_ctx = get_system_context()
    system_text = ASSISTANT_SYSTEM_PROMPT + "\n\n" + system_ctx

    payload = {
        'model': model,
        'max_tokens': 4096,
        'system': system_text,
        'messages': messages,
    }

    try:
        resp = http_requests.post(url, headers=headers, json=payload, timeout=120)
        data = resp.json()

        # If OAuth token expired, try refreshing
        if resp.status_code == 401 and oauth_token and refresh_token:
            new_token = refresh_oauth_token(refresh_token)
            if new_token:
                headers['Authorization'] = f'Bearer {new_token}'
                resp = http_requests.post(url, headers=headers, json=payload, timeout=120)
                data = resp.json()

        if resp.status_code != 200:
            error_msg = data.get('error', {}).get('message', resp.text)
            return None, f"API error ({resp.status_code}): {error_msg}"

        # Extract text from content blocks
        content_blocks = data.get('content', [])
        text_parts = []
        for block in content_blocks:
            if block.get('type') == 'text':
                text_parts.append(block['text'])
        return '\n'.join(text_parts), None

    except http_requests.exceptions.Timeout:
        return None, "Request timed out. Claude may be busy, try again."
    except http_requests.exceptions.ConnectionError:
        return None, "Connection error. Check internet connectivity."
    except Exception as e:
        return None, f"Request failed: {str(e)}"


def refresh_oauth_token(refresh_token):
    """Attempt to refresh an expired OAuth access token."""
    try:
        resp = http_requests.post(config.OAUTH_TOKEN_URL, data={
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': config.OAUTH_CLIENT_ID,
        }, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            new_access = data.get('access_token', '')
            new_refresh = data.get('refresh_token', refresh_token)
            if new_access:
                save_oauth_token(new_access, new_refresh)
                return new_access
    except Exception:
        pass
    return None


# --- OAuth routes ---

@app.route('/assistant/oauth/start')
@login_required
def oauth_start():
    """Begin Anthropic OAuth PKCE flow."""
    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(32)

    # Store in session for callback validation
    session['oauth_verifier'] = verifier
    session['oauth_state'] = state

    # Build the redirect URI using the request's host
    redirect_uri = request.url_root.rstrip('/') + config.OAUTH_REDIRECT_URI_BASE

    params = {
        'response_type': 'code',
        'client_id': config.OAUTH_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'scope': config.OAUTH_SCOPES,
        'state': state,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
    }
    auth_url = config.OAUTH_AUTHORIZE_URL + '?' + urllib.parse.urlencode(params)
    return redirect(auth_url)


@app.route('/assistant/oauth/callback')
@login_required
def oauth_callback():
    """Handle OAuth callback — exchange code for tokens."""
    code = request.args.get('code', '')
    state = request.args.get('state', '')
    error = request.args.get('error', '')

    if error:
        flash(f'OAuth error: {error}', 'error')
        return redirect(url_for('assistant'))

    # Validate state
    expected_state = session.pop('oauth_state', '')
    verifier = session.pop('oauth_verifier', '')
    if not state or state != expected_state:
        flash('OAuth state mismatch. Try again.', 'error')
        return redirect(url_for('assistant'))

    if not code or not verifier:
        flash('OAuth code or verifier missing. Try again.', 'error')
        return redirect(url_for('assistant'))

    redirect_uri = request.url_root.rstrip('/') + config.OAUTH_REDIRECT_URI_BASE

    # Exchange code for tokens
    try:
        resp = http_requests.post(config.OAUTH_TOKEN_URL, data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': config.OAUTH_CLIENT_ID,
            'code_verifier': verifier,
        }, timeout=15)

        if resp.status_code != 200:
            flash(f'Token exchange failed ({resp.status_code}): {resp.text[:200]}', 'error')
            return redirect(url_for('assistant'))

        data = resp.json()
        access_token = data.get('access_token', '')
        refresh_token = data.get('refresh_token', '')

        if not access_token:
            flash('No access token in response.', 'error')
            return redirect(url_for('assistant'))

        save_oauth_token(access_token, refresh_token)
        flash('OAuth connected successfully!', 'success')

    except Exception as e:
        flash(f'OAuth exchange failed: {str(e)}', 'error')

    return redirect(url_for('assistant'))


@app.route('/assistant/oauth/disconnect', methods=['POST'])
@login_required
def oauth_disconnect():
    """Remove stored OAuth tokens."""
    try:
        if os.path.exists(OAUTH_TOKEN_FILE):
            os.unlink(OAUTH_TOKEN_FILE)
    except Exception:
        pass
    return jsonify({'status': 'ok'})


# --- Assistant page & API ---

@app.route('/assistant')
@login_required
def assistant():
    api_key = load_api_key()
    oauth_token, _ = load_oauth_token()
    has_key = bool(api_key)
    has_oauth = bool(oauth_token)
    # Mask the key for display
    masked_key = ''
    if api_key:
        masked_key = api_key[:7] + '...' + api_key[-4:] if len(api_key) > 15 else '***'
    auth_method = get_auth_method()
    return render_template('assistant.html',
        has_key=has_key, masked_key=masked_key,
        has_oauth=has_oauth, auth_method=auth_method)


@app.route('/assistant/settings', methods=['POST'])
@login_required
def assistant_settings():
    api_key = request.json.get('api_key', '').strip()
    if not api_key:
        return jsonify({'error': 'No API key provided'}), 400
    if not api_key.startswith('sk-ant-'):
        return jsonify({'error': 'Invalid API key format. Should start with sk-ant-'}), 400
    try:
        with open(API_KEY_FILE, 'w') as f:
            f.write(api_key)
        os.chmod(API_KEY_FILE, 0o600)
        masked = api_key[:7] + '...' + api_key[-4:]
        return jsonify({'status': 'ok', 'masked_key': masked})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/assistant/send', methods=['POST'])
@login_required
def assistant_send():
    auth = get_auth_method()
    if not auth:
        return jsonify({'error': 'No API key or OAuth token configured. Add a key or connect via OAuth in Settings.'}), 400

    user_msg = request.json.get('message', '').strip()
    model = request.json.get('model', 'claude-sonnet-4-20250514')
    if not user_msg:
        return jsonify({'error': 'Empty message'}), 400

    allowed_models = [
        'claude-sonnet-4-20250514', 'claude-sonnet-4-5-20241022',
        'claude-opus-4-20250514', 'claude-opus-4-6-20250616',
        'claude-haiku-4-5-20251001',
    ]
    if model not in allowed_models:
        model = 'claude-sonnet-4-20250514'

    # Get conversation history from session (last 20 messages)
    if 'chat_history' not in session:
        session['chat_history'] = []

    session['chat_history'].append({'role': 'user', 'content': user_msg})

    # Keep only last 20 messages
    if len(session['chat_history']) > 20:
        session['chat_history'] = session['chat_history'][-20:]

    response_text, error = call_anthropic_api(model, session['chat_history'])

    if error:
        # Remove failed user message from history
        session['chat_history'].pop()
        session.modified = True
        return jsonify({'error': error}), 500

    session['chat_history'].append({'role': 'assistant', 'content': response_text})

    # Trim again after adding assistant response
    if len(session['chat_history']) > 20:
        session['chat_history'] = session['chat_history'][-20:]

    session.modified = True

    return jsonify({'response': response_text})


@app.route('/assistant/exec', methods=['POST'])
@login_required
def assistant_exec():
    cmd = request.json.get('command', '').strip()
    if not cmd:
        return jsonify({'error': 'Empty command'}), 400
    stdout, stderr, rc = run_cmd(cmd, timeout=30)
    output = stdout
    if stderr:
        output = output + '\n' + stderr if output else stderr
    return jsonify({'output': output or '(no output)', 'returncode': rc})


@app.route('/assistant/clear', methods=['POST'])
@login_required
def assistant_clear():
    session.pop('chat_history', None)
    session.modified = True
    return jsonify({'status': 'ok'})


# --- File Editor API ---

@app.route('/assistant/file/read', methods=['POST'])
@login_required
def assistant_file_read():
    """Read a file from anywhere on the filesystem."""
    filepath = request.json.get('path', '').strip()
    if not filepath:
        return jsonify({'error': 'No path specified'}), 400

    target = Path(filepath).resolve()
    if not target.exists():
        return jsonify({'error': f'File not found: {filepath}'}), 404
    if not target.is_file():
        return jsonify({'error': f'Not a file: {filepath}'}), 400
    if target.stat().st_size > MAX_FILE_SIZE:
        return jsonify({'error': f'File too large (max {MAX_FILE_SIZE // 1024 // 1024}MB)'}), 400

    try:
        with open(str(target), 'r', errors='replace') as f:
            content = f.read()
        return jsonify({'content': content, 'path': str(target)})
    except PermissionError:
        # Try with sudo cat
        stdout, stderr, rc = run_cmd(f'sudo cat {shlex.quote(str(target))}', timeout=10)
        if rc == 0:
            return jsonify({'content': stdout, 'path': str(target)})
        return jsonify({'error': f'Permission denied: {filepath}'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/assistant/file/write', methods=['POST'])
@login_required
def assistant_file_write():
    """Write content to a file anywhere on the filesystem."""
    filepath = request.json.get('path', '').strip()
    content = request.json.get('content', '')
    if not filepath:
        return jsonify({'error': 'No path specified'}), 400

    target = Path(filepath).resolve()

    # Create parent directories if needed
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        pass  # Will try sudo below

    try:
        with open(str(target), 'w') as f:
            f.write(content)
        return jsonify({'status': 'ok', 'path': str(target)})
    except PermissionError:
        # Write via sudo tee
        try:
            proc = subprocess.run(
                f'sudo tee {shlex.quote(str(target))}',
                shell=True, input=content, capture_output=True, text=True, timeout=10
            )
            if proc.returncode == 0:
                return jsonify({'status': 'ok', 'path': str(target)})
            return jsonify({'error': f'Permission denied (sudo failed): {proc.stderr}'}), 403
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- Network Info ---

@app.route('/network')
@login_required
def network():
    ip_out, _, _ = run_cmd("ip -4 addr show | grep 'inet ' | grep -v '127.0.0.1'")
    mac_out, _, _ = run_cmd("ip link show | grep 'link/ether'")
    gw_out, _, _ = run_cmd("ip route | grep default")
    dns_out, _, _ = run_cmd("grep '^nameserver' /etc/resolv.conf")

    return render_template('network.html',
        ip_info=ip_out,
        mac_info=mac_out,
        gateway=gw_out,
        dns=dns_out,
    )


@app.route('/api/ping/<target>')
@login_required
def api_ping(target):
    allowed = {'gateway': "ip route | grep default | awk '{print $3}'", '8.8.8.8': None}
    if target not in allowed:
        return jsonify({'error': 'Invalid target'}), 400

    if target == 'gateway':
        gw, _, rc = run_cmd(allowed['gateway'])
        if rc != 0 or not gw:
            return jsonify({'output': 'Could not determine gateway', 'success': False})
        target_ip = gw.split('\n')[0].strip()
    else:
        target_ip = '8.8.8.8'

    stdout, stderr, rc = run_cmd(f'ping -c 3 -W 3 {shlex.quote(target_ip)}', timeout=15)
    return jsonify({'output': stdout or stderr, 'success': rc == 0})


@app.route('/api/connections')
@login_required
def api_connections():
    stdout, _, _ = run_cmd('ss -tuln', timeout=10)
    return jsonify({'output': stdout})


# --- Package Manager ---

@app.route('/packages')
@login_required
def packages():
    return render_template('packages.html')


@app.route('/api/packages/search')
@login_required
def package_search():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({'results': []})
    safe_q = shlex.quote(query)
    stdout, stderr, rc = run_cmd(f'apt-cache search {safe_q} | head -50', timeout=15)
    results = []
    for line in stdout.splitlines():
        parts = line.split(' - ', 1)
        if len(parts) == 2:
            results.append({'name': parts[0].strip(), 'description': parts[1].strip()})
    return jsonify({'results': results})


@app.route('/api/packages/installed')
@login_required
def packages_installed():
    stdout, _, _ = run_cmd(
        "dpkg-query -W -f='${Package} ${Version} ${Status}\\n' | grep 'install ok installed' | head -200",
        timeout=15
    )
    packages = []
    for line in stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 2:
            packages.append({'name': parts[0], 'version': parts[1]})
    return jsonify({'packages': packages})


@app.route('/api/packages/install', methods=['POST'])
@login_required
def package_install():
    name = request.json.get('package', '').strip()
    if not name:
        return jsonify({'error': 'No package specified'}), 400
    safe_name = shlex.quote(name)
    stdout, stderr, rc = run_cmd(
        f'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {safe_name}',
        timeout=120
    )
    output = stdout
    if stderr:
        output = output + '\n' + stderr if output else stderr
    return jsonify({'output': output, 'success': rc == 0})


@app.route('/api/packages/remove', methods=['POST'])
@login_required
def package_remove():
    name = request.json.get('package', '').strip()
    if not name:
        return jsonify({'error': 'No package specified'}), 400
    safe_name = shlex.quote(name)
    stdout, stderr, rc = run_cmd(
        f'sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y {safe_name}',
        timeout=120
    )
    output = stdout
    if stderr:
        output = output + '\n' + stderr if output else stderr
    return jsonify({'output': output, 'success': rc == 0})


# --- Logs Viewer ---

@app.route('/logs')
@login_required
def logs():
    return render_template('logs.html')


@app.route('/api/logs')
@login_required
def api_logs():
    source = request.args.get('source', 'journalctl')
    lines = request.args.get('lines', '100')
    grep_filter = request.args.get('filter', '').strip()

    try:
        lines = min(int(lines), 500)
    except ValueError:
        lines = 100

    if source == 'journalctl':
        cmd = f'journalctl -n {lines} --no-pager'
    elif source == 'dmesg':
        cmd = f'dmesg | tail -n {lines}'
    elif source == 'syslog':
        cmd = f'tail -n {lines} /var/log/syslog 2>/dev/null || echo "syslog not available"'
    else:
        return jsonify({'error': 'Invalid source'}), 400

    if grep_filter:
        safe_filter = shlex.quote(grep_filter)
        cmd += f' | grep -i {safe_filter}'

    stdout, stderr, _ = run_cmd(cmd, timeout=15)
    return jsonify({'logs': stdout or stderr or 'No logs found'})


# --- Main ---

if __name__ == '__main__':
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
