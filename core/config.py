"""
ArchiveWraith - Configuration
Wayback-Only Mode
"""
import os
import hashlib

# Database
DATABASE_URL = os.environ.get('DATABASE_URL', None)
USE_POSTGRES = DATABASE_URL is not None and DATABASE_URL.startswith('postgresql')
DB_PATH = "archive_wraith.db"

# Auth
DEFAULT_USER = os.environ.get('ADMIN_USER', 'admin')
DEFAULT_PASS_HASH = hashlib.sha256(os.environ.get('ADMIN_PASS', 'wraith2025').encode()).hexdigest()
SECRET_KEY = os.environ.get('SECRET_KEY', 'archive-wraith-secret-2025')

# Wayback Check Workers
WAYBACK_WORKERS = int(os.environ.get('WAYBACK_WORKERS', '20'))
WAYBACK_TIMEOUT = int(os.environ.get('WAYBACK_TIMEOUT', '10'))

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDLIST_FILE = os.path.join(BASE_DIR, 'data', 'wordlist.txt')
