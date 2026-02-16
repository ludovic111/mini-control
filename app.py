#!/usr/bin/env python3
"""Mac Mini Control Panel - Flask Web Application"""

import ipaddress
import json
import os
import re
import secrets
import shlex
import subprocess
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import psutil
import requests as http_requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, send_file, flash, abort, Response, send_from_directory
)

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10GB uploads for movies
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

HISTORY_LIMIT = 720  # 60 minutes @ 5-second samples
STATS_INTERVAL = 5

CPU_HISTORY = []
RAM_HISTORY = []
DISK_IO_HISTORY = []
NET_HISTORY = []

HISTORY_LOCK = threading.Lock()
STATS_THREAD_LOCK = threading.Lock()
STATS_THREAD_STARTED = False

MOVIES_ROOT = Path('/home/ludovic/movies')
MOVIE_METADATA_CACHE_FILE = MOVIES_ROOT / '.metadata_cache.json'
OMDB_KEY_FILE = Path(os.path.expanduser('~/.mini-control-omdb-key'))
OMDB_API_BASE = 'http://www.omdbapi.com/'

VIDEO_EXTENSIONS = {'.mkv', '.mp4', '.avi', '.m4v', '.mov', '.wmv', '.flv', '.webm'}
MOVIE_NOISE_TOKENS = {
    '1080p', '720p', '2160p', '480p', '360p', '4k', '8k',
    'bluray', 'bdrip', 'brrip', 'webrip', 'webdl', 'web-dl', 'hdrip', 'hdtv', 'dvdrip',
    'x264', 'x265', 'h264', 'h265', 'hevc', 'xvid', 'aac', 'ac3', 'dts', 'ddp', 'atmos',
    'proper', 'repack', 'extended', 'unrated', 'remastered', 'remux',
    'yts', 'yify', 'rarbg', 'evo', 'etrg', 'nf', 'amzn',
    'multi', 'dubbed', 'subbed', 'dual', 'audio',
}
MOVIE_YEAR_RE = re.compile(r'(?<!\d)(19\d{2}|20\d{2})(?!\d)')

MOVIE_CACHE_LOCK = threading.Lock()

LOGIN_ATTEMPTS = {}
LOGIN_ATTEMPTS_LOCK = threading.Lock()
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_ATTEMPTS = 8
LOGIN_LOCK_SECONDS = 15 * 60


def parse_allowed_networks(raw_value):
    """Parse PANEL_ALLOWED_SUBNETS into a list of ip_network objects."""
    networks = []
    for entry in str(raw_value or '').split(','):
        token = entry.strip()
        if not token:
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return networks


ALLOWED_NETWORKS = parse_allowed_networks(config.ALLOWED_SUBNETS)


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


def get_client_identifier():
    """Return a stable identifier for rate limiting and network checks."""
    return (request.remote_addr or 'unknown').strip()


def is_client_ip_allowed(remote_addr):
    """Check whether the request source IP is inside configured private subnets."""
    if not ALLOWED_NETWORKS:
        return True

    try:
        client_ip = ipaddress.ip_address(str(remote_addr or '').strip())
    except ValueError:
        return False

    for network in ALLOWED_NETWORKS:
        if client_ip.version == network.version and client_ip in network:
            return True
        if (
            isinstance(client_ip, ipaddress.IPv6Address)
            and client_ip.ipv4_mapped
            and network.version == 4
            and client_ip.ipv4_mapped in network
        ):
            return True
    return False


def login_lock_remaining(client_id):
    """Return remaining lock duration in seconds for a client."""
    now = time.time()
    with LOGIN_ATTEMPTS_LOCK:
        state = LOGIN_ATTEMPTS.get(client_id)
        if not state:
            return 0
        locked_until = float(state.get('locked_until', 0) or 0)
        if locked_until <= now:
            return 0
        return int(locked_until - now)


def register_login_failure(client_id):
    """Record a failed login attempt and return lock-until timestamp or 0."""
    now = time.time()
    with LOGIN_ATTEMPTS_LOCK:
        state = LOGIN_ATTEMPTS.get(client_id)
        if not state or (now - float(state.get('first_attempt', now))) > LOGIN_WINDOW_SECONDS:
            state = {'count': 0, 'first_attempt': now, 'locked_until': 0}

        locked_until = float(state.get('locked_until', 0) or 0)
        if locked_until > now:
            LOGIN_ATTEMPTS[client_id] = state
            return locked_until

        state['count'] = int(state.get('count', 0) or 0) + 1
        state['first_attempt'] = float(state.get('first_attempt', now) or now)

        if state['count'] >= LOGIN_MAX_ATTEMPTS:
            state['count'] = 0
            state['first_attempt'] = now
            state['locked_until'] = now + LOGIN_LOCK_SECONDS
            LOGIN_ATTEMPTS[client_id] = state
            return state['locked_until']

        state['locked_until'] = 0
        LOGIN_ATTEMPTS[client_id] = state
        return 0


def clear_login_failures(client_id):
    """Clear failed login state for a client."""
    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS.pop(client_id, None)


def get_csrf_token():
    """Get or create a CSRF token in the current session."""
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
        session.modified = True
    return token


def get_request_csrf_token():
    """Extract CSRF token from request headers, form fields, or JSON body."""
    header_token = request.headers.get('X-CSRF-Token', '').strip()
    if header_token:
        return header_token

    form_token = request.form.get('_csrf_token', '').strip()
    if form_token:
        return form_token

    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        json_token = str(payload.get('_csrf_token') or '').strip()
        if json_token:
            return json_token
    return ''


def is_json_like_request():
    """Heuristic to decide whether an error should be returned as JSON."""
    if request.path.startswith('/api/'):
        return True
    if request.path.startswith('/movies/'):
        return True
    if request.is_json:
        return True
    accept = request.headers.get('Accept', '')
    return 'application/json' in accept.lower()


@app.context_processor
def inject_template_globals():
    """Expose CSRF token and feature flags to templates."""
    return {
        'csrf_token': get_csrf_token(),
        'feature_flags': {
            'enable_web_terminal': config.ENABLE_WEB_TERMINAL,
        },
    }


@app.after_request
def add_security_headers(response):
    """Attach browser-side hardening headers."""
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    return response


@app.before_request
def enforce_private_network_access():
    """Block public-network clients by default."""
    if request.endpoint == 'static':
        return None
    if is_client_ip_allowed(request.remote_addr):
        return None
    if is_json_like_request():
        return jsonify({'error': 'Access denied from this network'}), 403
    abort(403)


@app.before_request
def enforce_csrf():
    """Require CSRF token on state-changing requests."""
    if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
        return None
    expected = session.get('csrf_token', '')
    provided = get_request_csrf_token()
    if expected and provided and secrets.compare_digest(expected, provided):
        return None
    if is_json_like_request():
        return jsonify({'error': 'Invalid CSRF token'}), 400
    abort(400)


@app.before_request
def ensure_background_workers():
    """Ensure lightweight background workers are running."""
    start_stats_collector()


@app.errorhandler(413)
def payload_too_large(_error):
    """Return a friendly error when upload size exceeds MAX_CONTENT_LENGTH."""
    if request.path.startswith('/movies/upload'):
        return jsonify({'error': 'File is too large. Maximum upload size is 10GB.'}), 413
    return jsonify({'error': 'Request payload is too large'}), 413


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
    try:
        target.relative_to(root)
    except ValueError:
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


def is_video_file(path):
    """Return True when a file has a known movie/video extension."""
    return path.suffix.lower() in VIDEO_EXTENSIONS


def resolve_movie_path(relative_path):
    """Resolve a user-provided movie path inside MOVIES_ROOT."""
    if not relative_path:
        return None
    root = MOVIES_ROOT.resolve()
    candidate = (root / relative_path).resolve()
    if candidate == root:
        return None
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def load_omdb_key():
    """Load OMDb API key from ~/.mini-control-omdb-key."""
    try:
        if OMDB_KEY_FILE.exists():
            return OMDB_KEY_FILE.read_text(encoding='utf-8', errors='replace').strip()
    except Exception:
        return ''
    return ''


def save_omdb_key(api_key):
    """Persist OMDb API key to ~/.mini-control-omdb-key."""
    key = (api_key or '').strip()
    try:
        if not key:
            if OMDB_KEY_FILE.exists():
                OMDB_KEY_FILE.unlink()
            return True, 'OMDb API key removed'
        OMDB_KEY_FILE.write_text(key + '\n', encoding='utf-8')
        os.chmod(str(OMDB_KEY_FILE), 0o600)
        return True, 'OMDb API key saved'
    except Exception as exc:
        return False, str(exc)


def load_movie_metadata_cache():
    """Load cached movie metadata JSON."""
    try:
        if not MOVIE_METADATA_CACHE_FILE.exists():
            return {'version': 1, 'movies': {}}
        with open(MOVIE_METADATA_CACHE_FILE, 'r', encoding='utf-8', errors='replace') as f:
            payload = json.load(f)
        if not isinstance(payload, dict):
            return {'version': 1, 'movies': {}}
        movies = payload.get('movies')
        if not isinstance(movies, dict):
            payload['movies'] = {}
        return payload
    except Exception:
        return {'version': 1, 'movies': {}}


def save_movie_metadata_cache(cache_payload):
    """Save movie metadata cache atomically."""
    try:
        MOVIES_ROOT.mkdir(parents=True, exist_ok=True)
        tmp_path = MOVIE_METADATA_CACHE_FILE.with_suffix('.tmp')
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(cache_payload, f, indent=2, ensure_ascii=False)
        os.replace(str(tmp_path), str(MOVIE_METADATA_CACHE_FILE))
        return True
    except Exception:
        return False


def sanitize_movie_title_tokens(text):
    """Remove common release tags/noise from movie names."""
    cleaned_tokens = []
    for token in re.split(r'[\s._-]+', text.strip()):
        if not token:
            continue
        token_clean = re.sub(r'[^A-Za-z0-9]+', '', token)
        if not token_clean:
            continue
        lower = token_clean.lower()
        if lower in MOVIE_NOISE_TOKENS:
            continue
        if re.fullmatch(r'(19|20)\d{2}', lower):
            continue
        if re.fullmatch(r'\d{3,4}p', lower):
            continue
        if re.fullmatch(r'[xh]26[45]', lower):
            continue
        if re.fullmatch(r'\d+bit', lower):
            continue
        if re.fullmatch(r'cd\d+', lower):
            continue
        cleaned_tokens.append(token_clean)

    title = ' '.join(cleaned_tokens).strip()
    title = re.sub(r'\s+', ' ', title)
    return title


def parse_movie_filename(filename):
    """Infer title and year hints from a movie filename."""
    stem = Path(filename).stem
    year_hint = None

    year_match = MOVIE_YEAR_RE.search(stem)
    if year_match:
        try:
            year_hint = int(year_match.group(1))
        except Exception:
            year_hint = None

    title_hint = ''
    if year_match and year_match.start() > 0:
        title_hint = sanitize_movie_title_tokens(stem[:year_match.start()])
    if not title_hint:
        title_hint = sanitize_movie_title_tokens(stem)
    if not title_hint:
        title_hint = re.sub(r'[\._-]+', ' ', stem).strip()

    return title_hint or stem, year_hint


def extract_year_from_text(value):
    """Extract a 4-digit year from common OMDb year/date strings."""
    if not value:
        return None
    match = re.search(r'(19\d{2}|20\d{2})', str(value))
    if not match:
        return None
    try:
        return int(match.group(1))
    except Exception:
        return None


def parse_runtime_minutes(runtime_text):
    """Parse OMDb runtime like '142 min' into integer minutes."""
    if not runtime_text:
        return None
    match = re.search(r'(\d+)\s*min', str(runtime_text), re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except Exception:
        return None


def split_comma_field(value):
    """Split comma-separated OMDb fields into a list."""
    if not value or str(value).strip().lower() == 'n/a':
        return []
    return [part.strip() for part in str(value).split(',') if part.strip()]


def normalize_omdb_poster(value):
    """Normalize OMDb poster URL ('N/A' -> empty string)."""
    poster = str(value or '').strip()
    if not poster or poster.upper() == 'N/A':
        return ''
    return poster


def parse_omdb_rating(value):
    """Parse OMDb imdbRating into float or None."""
    rating_raw = str(value or '').strip()
    if not rating_raw or rating_raw.upper() == 'N/A':
        return None
    try:
        return round(float(rating_raw), 1)
    except Exception:
        return None


def omdb_request(params=None):
    """Perform a GET request against OMDb API."""
    api_key = load_omdb_key()
    if not api_key:
        return None, 'OMDb API key is not configured'

    request_params = dict(params or {})
    request_params['apikey'] = api_key

    try:
        response = http_requests.get(OMDB_API_BASE, params=request_params, timeout=15)
    except http_requests.RequestException as exc:
        return None, f'OMDb request failed: {exc}'

    if response.status_code >= 400:
        return None, f'OMDb API returned HTTP {response.status_code}'

    try:
        payload = response.json()
    except Exception:
        return None, 'OMDb returned invalid JSON'

    if str(payload.get('Response', 'True')).lower() == 'false':
        error_message = str(payload.get('Error') or 'OMDb query failed').strip()
        if 'invalid api key' in error_message.lower():
            return None, 'OMDb API key is invalid'
        return None, error_message

    return payload, None


def select_omdb_search_result(results, year_hint=None):
    """Pick the best OMDb search result with an optional year hint."""
    if not results:
        return None

    def score(result):
        value = 0
        result_year = extract_year_from_text(result.get('Year', ''))
        if year_hint and result_year == year_hint:
            value += 100
        elif year_hint and result_year and abs(result_year - year_hint) <= 1:
            value += 20
        if normalize_omdb_poster(result.get('Poster')):
            value += 1
        return value

    return max(results, key=score)


def normalize_omdb_metadata(payload):
    """Map OMDb movie details to the app's metadata structure."""
    poster_url = normalize_omdb_poster(payload.get('Poster'))
    return {
        'imdb_id': str(payload.get('imdbID') or '').strip(),
        'title': str(payload.get('Title') or '').strip(),
        'year': extract_year_from_text(payload.get('Year')),
        'overview': str(payload.get('Plot') or '').strip() if str(payload.get('Plot') or '').upper() != 'N/A' else '',
        'rating': parse_omdb_rating(payload.get('imdbRating')),
        'genres': split_comma_field(payload.get('Genre')),
        'runtime': parse_runtime_minutes(payload.get('Runtime')),
        'poster_url': poster_url,
        # OMDb does not provide backdrops. Reuse poster for hero background when available.
        'backdrop_url': poster_url,
        'director': str(payload.get('Director') or '').strip() if str(payload.get('Director') or '').upper() != 'N/A' else '',
        'actors': split_comma_field(payload.get('Actors')),
        'content_rating': str(payload.get('Rated') or '').strip() if str(payload.get('Rated') or '').upper() != 'N/A' else '',
    }


def fetch_omdb_metadata(title_hint, year_hint=None):
    """Search OMDb and return metadata for a single movie."""
    if not title_hint:
        return None, 'Could not infer movie title from filename'

    # 1) Try direct title (+optional year), best case = 1 request.
    details_params = {'t': title_hint}
    if year_hint:
        details_params['y'] = str(year_hint)
    details_payload, details_error = omdb_request(details_params)
    if details_payload:
        return normalize_omdb_metadata(details_payload), None

    # 2) Fallback search, then resolve via imdbID.
    search_payload, search_error = omdb_request({'s': title_hint, 'type': 'movie'})
    if search_error:
        if 'not found' in search_error.lower():
            return None, 'No OMDb match found for this filename'
        return None, search_error or details_error or 'No OMDb match found for this filename'

    results = (search_payload or {}).get('Search') or []
    if not results:
        return None, 'No OMDb match found for this filename'

    selected = select_omdb_search_result(results, year_hint=year_hint)
    if not selected:
        return None, 'No OMDb match found for this filename'

    imdb_id = str(selected.get('imdbID') or '').strip()
    if not imdb_id:
        return None, 'OMDb search result missing IMDb ID'

    details_payload, error = omdb_request({'i': imdb_id})
    if error:
        return None, error
    return normalize_omdb_metadata(details_payload), None


def build_movie_record(relative_path, file_path, stat_result, cache_entry):
    """Build API response object for a movie file."""
    metadata = cache_entry.get('metadata') if isinstance(cache_entry.get('metadata'), dict) else {}
    guessed_title = cache_entry.get('title_guess') or file_path.stem
    guessed_year = cache_entry.get('year_guess')
    rating = metadata.get('rating')
    if isinstance(rating, (int, float)):
        rating = round(float(rating), 1)
    else:
        rating = None

    runtime = metadata.get('runtime')
    if not isinstance(runtime, int):
        runtime = None

    year = metadata.get('year') if isinstance(metadata.get('year'), int) else guessed_year

    return {
        'filename': relative_path,
        'display_title': metadata.get('title') or guessed_title,
        'year': year,
        'overview': metadata.get('overview') or '',
        'rating': rating,
        'genres': metadata.get('genres') if isinstance(metadata.get('genres'), list) else [],
        'runtime': runtime,
        'poster_url': metadata.get('poster_url') or '',
        'backdrop_url': metadata.get('backdrop_url') or '',
        'imdb_id': metadata.get('imdb_id') or '',
        'director': metadata.get('director') or '',
        'actors': metadata.get('actors') if isinstance(metadata.get('actors'), list) else [],
        'content_rating': metadata.get('content_rating') or '',
        'file_size_bytes': int(stat_result.st_size),
        'file_size_human': format_bytes(stat_result.st_size),
        'file_path': str(file_path),
        'format': file_path.suffix.lower().replace('.', '').upper() or 'UNKNOWN',
        'modified_ts': int(stat_result.st_mtime),
        'modified_human': datetime.fromtimestamp(stat_result.st_mtime).strftime('%Y-%m-%d %H:%M'),
        'has_metadata': bool(metadata.get('title')),
    }


def sort_movies(movies, sort_key):
    """Sort movies by one of name/date/rating."""
    sort_key = (sort_key or 'date').strip().lower()
    if sort_key == 'name':
        return sorted(movies, key=lambda m: (m.get('display_title', '').lower(), m.get('filename', '').lower()))
    if sort_key == 'rating':
        return sorted(movies, key=lambda m: (float(m.get('rating') or 0.0), m.get('display_title', '').lower()), reverse=True)
    return sorted(movies, key=lambda m: (m.get('modified_ts') or 0, m.get('display_title', '').lower()), reverse=True)


def load_movies_index():
    """Scan movie directory and merge with metadata cache."""
    movies = []
    changed = False
    with MOVIE_CACHE_LOCK:
        cache = load_movie_metadata_cache()
        cache_movies = cache.get('movies')
        if not isinstance(cache_movies, dict):
            cache_movies = {}
            cache['movies'] = cache_movies

        seen = set()

        if MOVIES_ROOT.exists():
            for movie_path in MOVIES_ROOT.rglob('*'):
                if not movie_path.is_file() or not is_video_file(movie_path):
                    continue
                try:
                    stat_result = movie_path.stat()
                except OSError:
                    continue

                relative_path = str(movie_path.relative_to(MOVIES_ROOT))
                seen.add(relative_path)
                signature = f'{int(stat_result.st_size)}:{int(stat_result.st_mtime)}'
                title_hint, year_hint = parse_movie_filename(movie_path.name)
                existing_entry = cache_movies.get(relative_path)
                if not isinstance(existing_entry, dict):
                    existing_entry = {}
                    changed = True

                metadata = existing_entry.get('metadata') if isinstance(existing_entry.get('metadata'), dict) else {}
                new_entry = {
                    'signature': signature,
                    'title_guess': title_hint,
                    'year_guess': year_hint,
                    'metadata': metadata,
                    'omdb_updated_at': existing_entry.get('omdb_updated_at') or '',
                }

                if existing_entry != new_entry:
                    changed = True
                    cache_movies[relative_path] = new_entry

                movies.append(build_movie_record(relative_path, movie_path, stat_result, cache_movies[relative_path]))

        stale_paths = [path for path in list(cache_movies.keys()) if path not in seen]
        if stale_paths:
            changed = True
            for stale_path in stale_paths:
                cache_movies.pop(stale_path, None)

        if changed:
            cache['updated_at'] = datetime.now().isoformat(timespec='seconds')
            save_movie_metadata_cache(cache)

    return movies


def update_single_movie_cache(relative_path, metadata, title_hint, year_hint, signature):
    """Persist one movie metadata entry into the cache."""
    with MOVIE_CACHE_LOCK:
        cache = load_movie_metadata_cache()
        cache_movies = cache.get('movies')
        if not isinstance(cache_movies, dict):
            cache_movies = {}
            cache['movies'] = cache_movies
        cache_movies[relative_path] = {
            'signature': signature,
            'title_guess': title_hint,
            'year_guess': year_hint,
            'metadata': metadata or {},
            'omdb_updated_at': datetime.now().isoformat(timespec='seconds'),
        }
        cache['updated_at'] = datetime.now().isoformat(timespec='seconds')
        save_movie_metadata_cache(cache)


def remove_movie_from_cache(relative_path):
    """Remove one movie entry from the metadata cache."""
    with MOVIE_CACHE_LOCK:
        cache = load_movie_metadata_cache()
        cache_movies = cache.get('movies')
        if not isinstance(cache_movies, dict):
            return
        if relative_path in cache_movies:
            cache_movies.pop(relative_path, None)
            cache['updated_at'] = datetime.now().isoformat(timespec='seconds')
            save_movie_metadata_cache(cache)


# --- Auth routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    client_id = get_client_identifier()
    if request.method == 'POST':
        remaining = login_lock_remaining(client_id)
        if remaining > 0:
            minutes = max(1, int((remaining + 59) // 60))
            flash(f'Too many failed attempts. Try again in {minutes} minute(s).', 'error')
            return render_template('login.html'), 429

        if request.form.get('password') == config.PASSWORD:
            clear_login_failures(client_id)
            session['logged_in'] = True
            return redirect(url_for('dashboard'))

        lock_until = register_login_failure(client_id)
        if lock_until > time.time():
            flash('Too many failed attempts. Login temporarily locked.', 'error')
            return render_template('login.html'), 429
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
@login_required
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
    if not config.ENABLE_WEB_TERMINAL:
        flash('Web terminal is disabled by server policy.', 'error')
        return redirect(url_for('dashboard'))
    return render_template('terminal.html')


@app.route('/api/terminal', methods=['POST'])
@login_required
def api_terminal():
    if not config.ENABLE_WEB_TERMINAL:
        return jsonify({'error': 'Web terminal is disabled by server policy'}), 403
    data = request.get_json(silent=True) or {}
    cmd = str(data.get('command', '')).strip()
    if not cmd:
        return jsonify({'error': 'Empty command'}), 400
    stdout, stderr, rc = run_cmd(cmd, timeout=30)
    output = stdout
    if stderr:
        output = output + '\n' + stderr if output else stderr
    return jsonify({'output': output or '(no output)', 'returncode': rc})


# --- Movies ---

@app.route('/movies')
@login_required
def movies():
    return render_template(
        'movies.html',
        movies_root=str(MOVIES_ROOT),
        omdb_key_set=bool(load_omdb_key()),
    )


@app.route('/movies/api/list')
@login_required
def movies_api_list():
    sort_key = request.args.get('sort', 'date')
    search_query = request.args.get('q', '').strip().lower()

    movies_list = load_movies_index()
    if search_query:
        movies_list = [
            movie for movie in movies_list
            if search_query in str(movie.get('display_title', '')).lower()
            or search_query in str(movie.get('filename', '')).lower()
        ]
    movies_list = sort_movies(movies_list, sort_key)

    return jsonify({
        'movies': movies_list,
        'count': len(movies_list),
        'omdb_key_set': bool(load_omdb_key()),
        'movies_root': str(MOVIES_ROOT),
    })


@app.route('/movies/upload', methods=['POST'])
@login_required
def movies_upload():
    MOVIES_ROOT.mkdir(parents=True, exist_ok=True)
    uploaded = request.files.get('file')
    if not uploaded or uploaded.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    filename = Path(uploaded.filename).name
    if not filename:
        return jsonify({'error': 'Invalid filename'}), 400

    destination = MOVIES_ROOT / filename
    if destination.exists():
        return jsonify({'error': f'File already exists: {filename}'}), 409
    if not is_video_file(destination):
        return jsonify({'error': 'Unsupported video format'}), 400

    try:
        with open(destination, 'wb') as handle:
            while True:
                chunk = uploaded.stream.read(8 * 1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
    except Exception as exc:
        try:
            if destination.exists():
                destination.unlink()
        except Exception:
            pass
        return jsonify({'error': str(exc)}), 500

    relative_path = str(destination.relative_to(MOVIES_ROOT))
    movie_record = None
    metadata_error = None

    title_hint, year_hint = parse_movie_filename(destination.name)
    metadata, error = fetch_omdb_metadata(title_hint, year_hint=year_hint)
    if error:
        metadata_error = error
    else:
        try:
            stat_result = destination.stat()
            signature = f'{int(stat_result.st_size)}:{int(stat_result.st_mtime)}'
            update_single_movie_cache(relative_path, metadata, title_hint, year_hint, signature)
            cache_entry = {
                'signature': signature,
                'title_guess': title_hint,
                'year_guess': year_hint,
                'metadata': metadata,
            }
            movie_record = build_movie_record(relative_path, destination, stat_result, cache_entry)
        except Exception:
            movie_record = None

    return jsonify({
        'status': 'ok',
        'filename': relative_path,
        'movie': movie_record,
        'metadata_error': metadata_error,
    })


@app.route('/movies/api/metadata/<path:filename>')
@login_required
def movies_api_metadata(filename):
    movie_path = resolve_movie_path(filename)
    if movie_path is None:
        return jsonify({'error': 'Invalid movie path'}), 403
    if not movie_path.exists() or not movie_path.is_file():
        return jsonify({'error': 'Movie file not found'}), 404
    if not is_video_file(movie_path):
        return jsonify({'error': 'Not a supported video file'}), 400

    relative_path = str(movie_path.relative_to(MOVIES_ROOT))
    title_hint, year_hint = parse_movie_filename(movie_path.name)
    metadata, error = fetch_omdb_metadata(title_hint, year_hint=year_hint)
    if error:
        status_code = 502
        if 'not configured' in error.lower() or 'invalid' in error.lower():
            status_code = 400
        elif 'no omdb match' in error.lower() or 'could not infer' in error.lower():
            status_code = 404
        return jsonify({'error': error}), status_code

    try:
        stat_result = movie_path.stat()
    except OSError as exc:
        return jsonify({'error': str(exc)}), 500

    signature = f'{int(stat_result.st_size)}:{int(stat_result.st_mtime)}'
    update_single_movie_cache(relative_path, metadata, title_hint, year_hint, signature)
    cache_entry = {
        'signature': signature,
        'title_guess': title_hint,
        'year_guess': year_hint,
        'metadata': metadata,
    }

    return jsonify({
        'status': 'ok',
        'movie': build_movie_record(relative_path, movie_path, stat_result, cache_entry),
    })


@app.route('/movies/stream/<path:filename>')
@login_required
def movies_stream(filename):
    movie_path = resolve_movie_path(filename)
    if movie_path is None:
        abort(403)
    if not movie_path.exists() or not movie_path.is_file():
        abort(404)
    if not is_video_file(movie_path):
        abort(400)
    relative_path = str(movie_path.relative_to(MOVIES_ROOT))
    return send_from_directory(str(MOVIES_ROOT), relative_path, as_attachment=False, conditional=True)


@app.route('/movies/delete', methods=['POST'])
@login_required
def movies_delete():
    data = request_payload()
    filename = str(data.get('filename', '')).strip()
    movie_path = resolve_movie_path(filename)
    if movie_path is None:
        return jsonify({'error': 'Invalid movie path'}), 403
    if not movie_path.exists() or not movie_path.is_file():
        return jsonify({'error': 'Movie file not found'}), 404
    if not is_video_file(movie_path):
        return jsonify({'error': 'Only supported video files can be deleted here'}), 400

    relative_path = str(movie_path.relative_to(MOVIES_ROOT))
    try:
        movie_path.unlink()
        remove_movie_from_cache(relative_path)
        return jsonify({'status': 'ok', 'removed': relative_path})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@app.route('/movies/settings', methods=['POST'])
@login_required
def movies_settings():
    data = request_payload()
    omdb_key = str(data.get('omdb_key', '')).strip()
    ok, message = save_omdb_key(omdb_key)
    if not ok:
        return jsonify({'error': message}), 500
    return jsonify({
        'status': 'ok',
        'message': message,
        'omdb_key_set': bool(load_omdb_key()),
    })


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
