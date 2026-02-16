#!/usr/bin/env python3
"""Mac Mini Control Panel - Flask Web Application"""

import base64
import hashlib
import json
import os
import re
import secrets
import shlex
import signal
import subprocess
import threading
import time
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import psutil
import requests as http_requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, send_file, flash, abort, Response
)

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

HISTORY_LIMIT = 720  # 60 minutes @ 5-second samples
STATS_INTERVAL = 5

CPU_HISTORY = []
RAM_HISTORY = []
DISK_IO_HISTORY = []
NET_HISTORY = []

HISTORY_LOCK = threading.Lock()
STATS_THREAD_LOCK = threading.Lock()
STATS_THREAD_STARTED = False


def append_capped(history, entry):
    """Append a history entry and keep only the latest HISTORY_LIMIT points."""
    history.append(entry)
    if len(history) > HISTORY_LIMIT:
        del history[:-HISTORY_LIMIT]


def stats_collector_loop():
    """Collect CPU/RAM/disk I/O/network stats every STATS_INTERVAL seconds."""
    psutil.cpu_percent(interval=None)  # warm-up call for accurate next reading
    prev_ts = time.time()
    prev_disk = psutil.disk_io_counters()
    prev_net = psutil.net_io_counters()

    while True:
        loop_started = time.time()
        now_ts = int(loop_started)

        cpu_percent = round(psutil.cpu_percent(interval=None), 2)
        ram_percent = round(psutil.virtual_memory().percent, 2)

        disk_read_mb_s = 0.0
        disk_write_mb_s = 0.0
        net_recv_mb_s = 0.0
        net_sent_mb_s = 0.0

        disk_now = psutil.disk_io_counters()
        net_now = psutil.net_io_counters()
        elapsed = max(loop_started - prev_ts, 1e-6)

        if prev_disk and disk_now:
            disk_read_mb_s = max(disk_now.read_bytes - prev_disk.read_bytes, 0) / (1024 * 1024) / elapsed
            disk_write_mb_s = max(disk_now.write_bytes - prev_disk.write_bytes, 0) / (1024 * 1024) / elapsed

        if prev_net and net_now:
            net_recv_mb_s = max(net_now.bytes_recv - prev_net.bytes_recv, 0) / (1024 * 1024) / elapsed
            net_sent_mb_s = max(net_now.bytes_sent - prev_net.bytes_sent, 0) / (1024 * 1024) / elapsed

        with HISTORY_LOCK:
            append_capped(CPU_HISTORY, {'time': now_ts, 'value': cpu_percent})
            append_capped(RAM_HISTORY, {'time': now_ts, 'value': ram_percent})
            append_capped(DISK_IO_HISTORY, {
                'time': now_ts,
                'read': round(disk_read_mb_s, 3),
                'write': round(disk_write_mb_s, 3),
            })
            append_capped(NET_HISTORY, {
                'time': now_ts,
                'recv': round(net_recv_mb_s, 3),
                'sent': round(net_sent_mb_s, 3),
            })

        prev_ts = loop_started
        prev_disk = disk_now
        prev_net = net_now

        sleep_for = STATS_INTERVAL - (time.time() - loop_started)
        if sleep_for > 0:
            time.sleep(sleep_for)


def start_stats_collector():
    """Start background metrics collector once per process."""
    global STATS_THREAD_STARTED
    with STATS_THREAD_LOCK:
        if STATS_THREAD_STARTED:
            return
        if app.debug and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
            return
        STATS_THREAD_STARTED = True
        thread = threading.Thread(
            target=stats_collector_loop,
            daemon=True,
            name='mini-control-stats'
        )
        thread.start()


# --- Auth decorator ---

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


@app.before_request
def ensure_background_workers():
    """Ensure lightweight background workers are running."""
    start_stats_collector()


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


def request_payload():
    """Get request payload from JSON body or form fields."""
    return request.get_json(silent=True) or request.form


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


def validate_new_entry_name(name):
    """Validate a new file/folder name for the file manager."""
    if not name:
        return 'Name is required'
    if name in ('.', '..'):
        return 'Invalid name'
    if '/' in name or '\\' in name:
        return 'Name cannot contain path separators'
    if '\x00' in name:
        return 'Invalid name'
    return None


def parse_log_lines(raw_lines):
    """Parse and clamp logs line count."""
    try:
        return min(max(int(raw_lines), 1), 500)
    except ValueError:
        return 100


def build_logs_cmd(source, lines, grep_filter=''):
    """Build log retrieval shell command."""
    if source == 'journalctl':
        cmd = f'journalctl -n {lines} --no-pager'
    elif source == 'dmesg':
        cmd = f'dmesg | tail -n {lines}'
    elif source == 'syslog':
        cmd = f'tail -n {lines} /var/log/syslog 2>/dev/null || echo "syslog not available"'
    else:
        return None, 'Invalid source'

    if grep_filter:
        safe_filter = shlex.quote(grep_filter)
        cmd += f' | grep -i {safe_filter}'
    return cmd, None


def format_uptime():
    """Return a short uptime string."""
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime_delta = datetime.now() - boot_time
    days = uptime_delta.days
    hours, remainder = divmod(uptime_delta.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m"


def get_scheduled_shutdown():
    """Inspect systemd scheduled shutdown metadata."""
    schedule_file = Path('/run/systemd/shutdown/scheduled')
    if not schedule_file.exists():
        return {'scheduled': False}

    details = {'scheduled': True}
    try:
        content = schedule_file.read_text(encoding='utf-8', errors='replace')
        for line in content.splitlines():
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip().lower()
            value = value.strip()
            if key == 'mode':
                details['mode'] = value
            elif key == 'usec':
                try:
                    at_dt = datetime.fromtimestamp(int(value) / 1_000_000)
                    details['at'] = at_dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass
    except Exception:
        return {'scheduled': True}
    return details


def collect_dashboard_stats(cpu_interval=0.2):
    """Collect dashboard metrics payload."""
    cpu_percent = psutil.cpu_percent(interval=cpu_interval)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    load_avg = os.getloadavg()
    scheduled_shutdown = get_scheduled_shutdown()

    return {
        'cpu_percent': round(cpu_percent, 1),
        'mem_used': format_bytes(mem.used),
        'mem_total': format_bytes(mem.total),
        'mem_percent': round(mem.percent, 1),
        'disk_used': format_bytes(disk.used),
        'disk_total': format_bytes(disk.total),
        'disk_percent': round(disk.percent, 1),
        'uptime': format_uptime(),
        'cpu_temp': get_cpu_temp(),
        'load_avg': f"{load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}",
        'ssh_active': check_service('ssh'),
        'panel_active': check_service('mini-control'),
        'scheduled_shutdown': scheduled_shutdown,
    }


def load_git_updates(limit=500):
    """Load git commit history for the changelog page."""
    repo_root = Path(__file__).resolve().parent
    commits = []
    try:
        result = subprocess.run(
            [
                'git', '-C', str(repo_root), 'log',
                '--date=short',
                '--pretty=format:%h%x1f%ad%x1f%an%x1f%s'
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )
        if result.returncode != 0:
            return commits

        for line in result.stdout.splitlines():
            parts = line.split('\x1f')
            if len(parts) != 4:
                continue
            commits.append({
                'short_hash': parts[0],
                'date': parts[1],
                'author': parts[2],
                'subject': parts[3],
            })
            if len(commits) >= limit:
                break
    except Exception:
        return []
    return commits


def load_changelog_notes():
    """Load local CHANGELOG.md content if present."""
    path = Path(__file__).resolve().parent / 'CHANGELOG.md'
    try:
        if path.exists():
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
    except Exception:
        pass
    return ''


CRON_LABEL_PREFIX = '# mini-control:'
SPECIAL_CRON_EXPANSIONS = {
    '@reboot': None,
    '@hourly': '0 * * * *',
    '@daily': '0 0 * * *',
    '@weekly': '0 0 * * 0',
    '@monthly': '0 0 1 * *',
    '@yearly': '0 0 1 1 *',
    '@annually': '0 0 1 1 *',
}
MONTH_NAME_MAP = {
    'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4,
    'may': 5, 'jun': 6, 'jul': 7, 'aug': 8,
    'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12,
}
WEEKDAY_NAME_MAP = {
    'sun': 0, 'mon': 1, 'tue': 2, 'wed': 3,
    'thu': 4, 'fri': 5, 'sat': 6,
}


def parse_cron_value(token, minimum, maximum, name_map=None):
    """Parse a cron field token into an integer."""
    key = token.strip().lower()
    if name_map and key in name_map:
        value = name_map[key]
    elif re.fullmatch(r'\d+', key):
        value = int(key)
    else:
        raise ValueError('Invalid cron token')
    if value < minimum or value > maximum:
        raise ValueError('Cron token out of range')
    return value


def parse_cron_field(field, minimum, maximum, name_map=None):
    """Parse a single cron field into a set of allowed values."""
    field = field.strip().lower()
    if not field:
        raise ValueError('Empty cron field')

    any_value = field == '*'
    values = set()

    for part in field.split(','):
        part = part.strip()
        if not part:
            raise ValueError('Invalid cron list')

        step = 1
        base = part
        if '/' in part:
            base, step_raw = part.split('/', 1)
            if not re.fullmatch(r'\d+', step_raw):
                raise ValueError('Invalid cron step')
            step = int(step_raw)
            if step <= 0:
                raise ValueError('Invalid cron step')

        if base == '*':
            start, end = minimum, maximum
        elif '-' in base:
            left, right = base.split('-', 1)
            start = parse_cron_value(left, minimum, maximum, name_map)
            end = parse_cron_value(right, minimum, maximum, name_map)
            if start > end:
                raise ValueError('Invalid cron range')
        else:
            value = parse_cron_value(base, minimum, maximum, name_map)
            start, end = value, value

        for value in range(start, end + 1, step):
            values.add(value)

    if maximum == 7 and 7 in values:
        values.discard(7)
        values.add(0)

    return values, any_value


def parse_standard_cron(schedule):
    """Parse a 5-field cron expression."""
    parts = schedule.split()
    if len(parts) != 5:
        return None

    try:
        minute_values, minute_any = parse_cron_field(parts[0], 0, 59)
        hour_values, hour_any = parse_cron_field(parts[1], 0, 23)
        dom_values, dom_any = parse_cron_field(parts[2], 1, 31)
        month_values, month_any = parse_cron_field(parts[3], 1, 12, MONTH_NAME_MAP)
        dow_values, dow_any = parse_cron_field(parts[4], 0, 7, WEEKDAY_NAME_MAP)
    except ValueError:
        return None

    return {
        'minute_values': minute_values,
        'hour_values': hour_values,
        'dom_values': dom_values,
        'month_values': month_values,
        'dow_values': dow_values,
        'minute_any': minute_any,
        'hour_any': hour_any,
        'dom_any': dom_any,
        'month_any': month_any,
        'dow_any': dow_any,
    }


def normalize_cron_schedule(schedule):
    """Expand special cron shorthands to 5-field format when applicable."""
    schedule = schedule.strip().lower()
    if schedule in SPECIAL_CRON_EXPANSIONS:
        expanded = SPECIAL_CRON_EXPANSIONS[schedule]
        return schedule, expanded
    return schedule, schedule


def is_valid_cron_schedule(schedule):
    """Validate cron schedule string."""
    schedule_key, expanded = normalize_cron_schedule(schedule)
    if schedule_key == '@reboot':
        return True
    if not expanded:
        return False
    return parse_standard_cron(expanded) is not None


def cron_matches(parsed, dt):
    """Check whether parsed cron fields match a datetime."""
    cron_dow = (dt.weekday() + 1) % 7  # Python Monday=0..Sunday=6 -> cron Sunday=0

    if dt.minute not in parsed['minute_values']:
        return False
    if dt.hour not in parsed['hour_values']:
        return False
    if dt.month not in parsed['month_values']:
        return False

    dom_match = dt.day in parsed['dom_values']
    dow_match = cron_dow in parsed['dow_values']

    if parsed['dom_any'] and parsed['dow_any']:
        return True
    if parsed['dom_any']:
        return dow_match
    if parsed['dow_any']:
        return dom_match
    return dom_match or dow_match


def get_next_cron_run(schedule, now=None):
    """Calculate next run for a cron schedule."""
    schedule_key, expanded = normalize_cron_schedule(schedule)
    if schedule_key == '@reboot':
        return None

    parsed = parse_standard_cron(expanded)
    if not parsed:
        return None

    now = now or datetime.now()
    candidate = now.replace(second=0, microsecond=0) + timedelta(minutes=1)

    max_checks = 366 * 24 * 60
    for _ in range(max_checks):
        if cron_matches(parsed, candidate):
            return candidate
        candidate += timedelta(minutes=1)
    return None


def parse_cron_job_line(stripped_line):
    """Parse a crontab line into schedule + command if it is a job line."""
    if not stripped_line or stripped_line.startswith('#'):
        return None

    if stripped_line.startswith('@'):
        parts = stripped_line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in SPECIAL_CRON_EXPANSIONS:
            return {
                'schedule': parts[0].lower(),
                'command': parts[1].strip(),
            }
        return None

    parts = stripped_line.split(None, 5)
    if len(parts) < 6:
        return None

    schedule = ' '.join(parts[:5]).strip()
    command = parts[5].strip()
    if not command:
        return None
    if parse_standard_cron(schedule) is None:
        return None

    return {'schedule': schedule, 'command': command}


def read_crontab_lines():
    """Read current user crontab as list of lines."""
    try:
        result = subprocess.run(
            ['crontab', '-l'],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )
    except FileNotFoundError:
        raise RuntimeError('crontab command not found')
    except Exception as exc:
        raise RuntimeError(str(exc))

    if result.returncode != 0:
        stderr = (result.stderr or '').strip()
        if 'no crontab for' in stderr.lower():
            return []
        raise RuntimeError(stderr or 'Failed to read crontab')

    return result.stdout.splitlines()


def parse_crontab_entries(lines):
    """Parse full crontab lines into editable entries while preserving raw lines."""
    entries = []
    pending_label = ''
    job_id = 0

    for line in lines:
        stripped = line.strip()
        if stripped.lower().startswith(CRON_LABEL_PREFIX):
            pending_label = stripped[len(CRON_LABEL_PREFIX):].strip()
            continue

        parsed = parse_cron_job_line(stripped)
        if parsed:
            job_id += 1
            entries.append({
                'type': 'job',
                'id': job_id,
                'schedule': parsed['schedule'],
                'command': parsed['command'],
                'label': pending_label,
            })
            pending_label = ''
            continue

        if pending_label:
            entries.append({'type': 'raw', 'line': f'{CRON_LABEL_PREFIX} {pending_label}'})
            pending_label = ''

        entries.append({'type': 'raw', 'line': line})

    if pending_label:
        entries.append({'type': 'raw', 'line': f'{CRON_LABEL_PREFIX} {pending_label}'})

    return entries


def render_crontab_entries(entries):
    """Render entries back into crontab text."""
    lines = []
    for entry in entries:
        if entry.get('type') == 'raw':
            lines.append(entry.get('line', ''))
            continue

        label = (entry.get('label') or '').strip()
        if label:
            lines.append(f'{CRON_LABEL_PREFIX} {label}')
        schedule = (entry.get('schedule') or '').strip()
        command = (entry.get('command') or '').strip()
        if schedule and command:
            lines.append(f'{schedule} {command}')

    if not lines:
        return ''
    return '\n'.join(lines).rstrip() + '\n'


def write_crontab_entries(entries):
    """Write entries to crontab."""
    content = render_crontab_entries(entries)

    if not content.strip():
        result = subprocess.run(
            ['crontab', '-r'],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )
        if result.returncode != 0 and 'no crontab for' not in (result.stderr or '').lower():
            raise RuntimeError((result.stderr or 'Failed to clear crontab').strip())
        return

    result = subprocess.run(
        ['crontab', '-'],
        input=content,
        capture_output=True,
        text=True,
        timeout=10,
        check=False
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or 'Failed to write crontab').strip())


def load_scheduler_jobs():
    """Load parsed scheduler jobs for UI display."""
    lines = read_crontab_lines()
    entries = parse_crontab_entries(lines)
    jobs = []

    for entry in entries:
        if entry.get('type') != 'job':
            continue

        schedule = entry['schedule']
        next_run = get_next_cron_run(schedule)
        if schedule == '@reboot':
            next_run_str = 'At reboot'
        elif next_run is None:
            next_run_str = 'N/A'
        else:
            next_run_str = next_run.strftime('%Y-%m-%d %H:%M')

        jobs.append({
            'id': entry['id'],
            'label': entry.get('label', ''),
            'schedule': schedule,
            'command': entry['command'],
            'next_run': next_run_str,
        })

    return entries, jobs, '\n'.join(lines)


def sanitize_schedule_input(schedule):
    """Normalize and validate schedule input."""
    normalized = ' '.join(schedule.strip().split())
    if not normalized:
        return None, 'Schedule is required'

    key, expanded = normalize_cron_schedule(normalized)
    if key.startswith('@'):
        normalized = key
    else:
        normalized = expanded

    if not is_valid_cron_schedule(normalized):
        return None, 'Invalid cron expression'
    return normalized, None


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
    stats = collect_dashboard_stats(cpu_interval=0.4)
    return render_template('dashboard.html', **stats)


@app.route('/api/dashboard')
@login_required
def api_dashboard():
    # Backward-compatible endpoint for older frontend code.
    return api_stats()


@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(collect_dashboard_stats(cpu_interval=0.2))


@app.route('/api/history')
@login_required
def api_history():
    with HISTORY_LOCK:
        return jsonify({
            'cpu_history': list(CPU_HISTORY),
            'ram_history': list(RAM_HISTORY),
            'disk_io_history': list(DISK_IO_HISTORY),
            'net_history': list(NET_HISTORY),
        })


@app.route('/api/power/reboot', methods=['POST'])
@login_required
def api_power_reboot():
    stdout, stderr, rc = run_cmd('sudo /sbin/reboot', timeout=10)
    if rc != 0:
        stdout, stderr, rc = run_cmd('sudo reboot', timeout=10)
    if rc != 0:
        return jsonify({'error': stderr or 'Failed to trigger reboot'}), 500
    return jsonify({'status': 'ok', 'message': stdout or 'Reboot command sent'})


@app.route('/api/power/shutdown', methods=['POST'])
@login_required
def api_power_shutdown():
    stdout, stderr, rc = run_cmd('sudo /sbin/shutdown -h now', timeout=10)
    if rc != 0:
        stdout, stderr, rc = run_cmd('sudo shutdown -h now', timeout=10)
    if rc != 0:
        return jsonify({'error': stderr or 'Failed to trigger shutdown'}), 500
    return jsonify({'status': 'ok', 'message': stdout or 'Shutdown command sent'})


@app.route('/api/power/schedule', methods=['POST'])
@login_required
def api_power_schedule():
    data = request.get_json(silent=True) or {}
    minutes_raw = str(data.get('minutes', '')).strip()
    if not minutes_raw.isdigit():
        return jsonify({'error': 'Minutes must be a positive integer'}), 400

    minutes = int(minutes_raw)
    if minutes < 1 or minutes > 7 * 24 * 60:
        return jsonify({'error': 'Minutes must be between 1 and 10080'}), 400

    stdout, stderr, rc = run_cmd(f'sudo /sbin/shutdown -r +{minutes}', timeout=10)
    if rc != 0:
        stdout, stderr, rc = run_cmd(f'sudo shutdown -r +{minutes}', timeout=10)
    if rc != 0:
        return jsonify({'error': stderr or 'Failed to schedule reboot'}), 500

    return jsonify({
        'status': 'ok',
        'message': stdout or f'Reboot scheduled in {minutes} minute(s)',
        'scheduled_shutdown': get_scheduled_shutdown(),
    })


@app.route('/api/power/cancel', methods=['POST'])
@login_required
def api_power_cancel():
    stdout, stderr, rc = run_cmd('sudo /sbin/shutdown -c', timeout=10)
    if rc != 0:
        stdout, stderr, rc = run_cmd('sudo shutdown -c', timeout=10)
    if rc != 0:
        return jsonify({'error': stderr or 'Failed to cancel shutdown'}), 500
    return jsonify({'status': 'ok', 'message': stdout or 'Scheduled shutdown cancelled'})


@app.route('/api/power/ping')
def api_power_ping():
    return jsonify({'online': True, 'ts': int(time.time())})


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


@app.route('/files/create-folder/<path:subpath>', methods=['POST'])
@login_required
def create_folder(subpath=''):
    target_dir = safe_path(subpath)
    if target_dir is None:
        return jsonify({'error': 'Access denied'}), 403
    if not target_dir.is_dir():
        return jsonify({'error': 'Not a directory'}), 400

    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip()
    err = validate_new_entry_name(name)
    if err:
        return jsonify({'error': err}), 400

    new_dir = target_dir / name
    if new_dir.exists():
        return jsonify({'error': 'Already exists'}), 409

    try:
        new_dir.mkdir()
        return jsonify({'status': 'ok', 'name': name})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/files/create-folder', methods=['POST'])
@login_required
def create_folder_root():
    return create_folder('')


@app.route('/files/create-file/<path:subpath>', methods=['POST'])
@login_required
def create_file(subpath=''):
    target_dir = safe_path(subpath)
    if target_dir is None:
        return jsonify({'error': 'Access denied'}), 403
    if not target_dir.is_dir():
        return jsonify({'error': 'Not a directory'}), 400

    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip()
    content = data.get('content', '')
    err = validate_new_entry_name(name)
    if err:
        return jsonify({'error': err}), 400

    new_file = target_dir / name
    if new_file.exists():
        return jsonify({'error': 'Already exists'}), 409

    try:
        with open(new_file, 'x') as f:
            f.write(content)
        return jsonify({'status': 'ok', 'name': name})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/files/create-file', methods=['POST'])
@login_required
def create_file_root():
    return create_file('')


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


# --- Scheduler ---

@app.route('/scheduler')
@login_required
def scheduler():
    try:
        _, jobs, raw_crontab = load_scheduler_jobs()
    except RuntimeError as exc:
        flash(str(exc), 'error')
        jobs = []
        raw_crontab = ''

    return render_template(
        'scheduler.html',
        jobs=jobs,
        raw_crontab=raw_crontab,
    )


@app.route('/scheduler/add', methods=['POST'])
@login_required
def scheduler_add():
    data = request_payload()
    schedule_raw = str(data.get('schedule', '')).strip()
    command = str(data.get('command', '')).strip()
    label = str(data.get('label', '')).strip().replace('\n', ' ').replace('\r', ' ')

    if not command:
        return jsonify({'error': 'Command is required'}), 400

    schedule, err = sanitize_schedule_input(schedule_raw)
    if err:
        return jsonify({'error': err}), 400

    try:
        entries = parse_crontab_entries(read_crontab_lines())
        entries.append({
            'type': 'job',
            'schedule': schedule,
            'command': command,
            'label': label,
        })
        write_crontab_entries(entries)
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 500

    return jsonify({'status': 'ok'})


@app.route('/scheduler/edit', methods=['POST'])
@login_required
def scheduler_edit():
    data = request_payload()
    job_id_raw = str(data.get('job_id', '')).strip()
    schedule_raw = str(data.get('schedule', '')).strip()
    command = str(data.get('command', '')).strip()
    label = str(data.get('label', '')).strip().replace('\n', ' ').replace('\r', ' ')

    if not job_id_raw.isdigit():
        return jsonify({'error': 'Invalid job id'}), 400
    if not command:
        return jsonify({'error': 'Command is required'}), 400

    schedule, err = sanitize_schedule_input(schedule_raw)
    if err:
        return jsonify({'error': err}), 400

    job_id = int(job_id_raw)

    try:
        entries = parse_crontab_entries(read_crontab_lines())
        found = False
        for entry in entries:
            if entry.get('type') == 'job' and entry.get('id') == job_id:
                entry['schedule'] = schedule
                entry['command'] = command
                entry['label'] = label
                found = True
                break

        if not found:
            return jsonify({'error': 'Job not found'}), 404

        write_crontab_entries(entries)
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 500

    return jsonify({'status': 'ok'})


@app.route('/scheduler/delete', methods=['POST'])
@login_required
def scheduler_delete():
    data = request_payload()
    job_id_raw = str(data.get('job_id', '')).strip()

    if not job_id_raw.isdigit():
        return jsonify({'error': 'Invalid job id'}), 400

    job_id = int(job_id_raw)

    try:
        entries = parse_crontab_entries(read_crontab_lines())
        kept = []
        found = False
        for entry in entries:
            if entry.get('type') == 'job' and entry.get('id') == job_id:
                found = True
                continue
            kept.append(entry)

        if not found:
            return jsonify({'error': 'Job not found'}), 404

        write_crontab_entries(kept)
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 500

    return jsonify({'status': 'ok'})


# --- Logs Viewer ---

@app.route('/logs')
@login_required
def logs():
    return render_template('logs.html')


@app.route('/changelog')
@login_required
def changelog():
    commits = load_git_updates()
    notes = load_changelog_notes()
    return render_template(
        'changelog.html',
        commits=commits,
        notes=notes,
    )


@app.route('/api/logs')
@login_required
def api_logs():
    source = request.args.get('source', 'journalctl')
    lines = parse_log_lines(request.args.get('lines', '100'))
    grep_filter = request.args.get('filter', '').strip()

    cmd, err = build_logs_cmd(source, lines, grep_filter)
    if err:
        return jsonify({'error': err}), 400

    stdout, stderr, _ = run_cmd(cmd, timeout=15)
    return jsonify({'logs': stdout or stderr or 'No logs found'})


@app.route('/api/logs/download')
@login_required
def api_logs_download():
    source = request.args.get('source', 'journalctl')
    lines = parse_log_lines(request.args.get('lines', '100'))
    grep_filter = request.args.get('filter', '').strip()

    cmd, err = build_logs_cmd(source, lines, grep_filter)
    if err:
        return jsonify({'error': err}), 400

    stdout, stderr, _ = run_cmd(cmd, timeout=15)
    logs = stdout or stderr or 'No logs found'
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    filename = f'{source}-{timestamp}.log'
    return Response(
        logs + '\n',
        mimetype='text/plain; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


# --- Main ---

if __name__ == '__main__':
    start_stats_collector()
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
