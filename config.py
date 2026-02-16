import os
import secrets
from pathlib import Path


def _load_or_create_secret(path, length):
    """Load a secret from file, creating a new one if missing."""
    target = Path(path).expanduser()
    try:
        if target.exists():
            value = target.read_text(encoding='utf-8', errors='replace').strip()
            if value:
                return value
    except Exception:
        pass

    value = secrets.token_urlsafe(length)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value + '\n', encoding='utf-8')
        os.chmod(str(target), 0o600)
    except Exception:
        # Fallback to in-memory secret if file cannot be written.
        return value
    return value


SECRET_KEY = os.environ.get('SECRET_KEY') or _load_or_create_secret('~/.mini-control-secret-key', 48)
PASSWORD = os.environ.get('PANEL_PASSWORD') or _load_or_create_secret('~/.mini-control-password', 24)
HOST = os.environ.get('PANEL_HOST', '0.0.0.0')
PORT = int(os.environ.get('PANEL_PORT', '5000'))
DEBUG = os.environ.get('PANEL_DEBUG', 'false').strip().lower() in ('1', 'true', 'yes')
FILE_ROOT = os.environ.get('FILE_ROOT', '/home/ludovic')

# Allow private LAN ranges by default, block public internet clients at app layer.
ALLOWED_SUBNETS = os.environ.get(
    'PANEL_ALLOWED_SUBNETS',
    '127.0.0.1/32,::1/128,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12'
)

# Sensitive feature flags (disabled by default).
ENABLE_WEB_TERMINAL = os.environ.get('ENABLE_WEB_TERMINAL', 'false').strip().lower() in ('1', 'true', 'yes')
ENABLE_ASSISTANT_EXEC = os.environ.get('ENABLE_ASSISTANT_EXEC', 'false').strip().lower() in ('1', 'true', 'yes')
ENABLE_ASSISTANT_FILE_EDITOR = os.environ.get('ENABLE_ASSISTANT_FILE_EDITOR', 'false').strip().lower() in ('1', 'true', 'yes')

# Anthropic OAuth settings
OAUTH_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e'
OAUTH_AUTHORIZE_URL = 'https://console.anthropic.com/oauth/authorize'
OAUTH_TOKEN_URL = 'https://console.anthropic.com/v1/oauth/token'
OAUTH_REDIRECT_URI_BASE = '/assistant/oauth/callback'
OAUTH_SCOPES = 'org:create_api_key user:profile user:inference'
