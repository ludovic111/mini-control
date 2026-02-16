import os

SECRET_KEY = os.environ.get('SECRET_KEY', 'mini-control-secret-key-change-me')
PASSWORD = os.environ.get('PANEL_PASSWORD', 'minilinux2006')
HOST = '0.0.0.0'
PORT = 5000
DEBUG = False
FILE_ROOT = '/home/ludovic'

# Anthropic OAuth settings
OAUTH_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e'
OAUTH_AUTHORIZE_URL = 'https://console.anthropic.com/oauth/authorize'
OAUTH_TOKEN_URL = 'https://console.anthropic.com/v1/oauth/token'
OAUTH_REDIRECT_URI_BASE = '/assistant/oauth/callback'
OAUTH_SCOPES = 'org:create_api_key user:profile user:inference'
