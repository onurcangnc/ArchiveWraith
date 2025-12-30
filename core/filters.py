"""
Temporal Recon v5.7 - URL Filtering
===================================
Extension filter + Wordlist path filter
"""
import re
from urllib.parse import urlparse
from .config import WORDLIST_FILE

# ============================================================================
# WORDLIST LOADING
# ============================================================================

def load_wordlist(filepath):
    """Load wordlist into set for O(1) lookup"""
    paths = set()
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for line in f:
                p = line.strip().lower().strip('/')
                if p and len(p) >= 2:
                    paths.add(p)
        print(f"[✓] Wordlist: {len(paths):,} paths")
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {filepath}")
    except Exception as e:
        print(f"[!] Wordlist error: {e}")
    return paths

# Load at import time
SENSITIVE_PATHS = load_wordlist(WORDLIST_FILE)

# ============================================================================
# EXTENSION PATTERNS
# ============================================================================

CDX_FILTER_EXTENSIONS = (
    "sql|db|db3|sqlite|sqlite3|sqlitedb|mdb|ldb|accdb|dump|dmp|"
    "env|envrc|secret|secrets|password|passwords|passwd|credential|credentials|"
    "pem|crt|key|p12|pfx|jks|keystore|pub|asc|ppk|"
    "bak|bak1|bak2|backup|old|old1|old2|orig|original|save|saved|copy|tmp|temp|swp|"
    "git|gitignore|gitconfig|git-credentials|svn|hg|bzr|cvs|"
    "tfstate|tfvars|kubeconfig|dockerenv|htpasswd|htaccess|"
    "bash_history|zsh_history|mysql_history|psql_history|npmrc|pypirc|netrc|pgpass|"
    "config|conf|cfg|ini|yaml|yml|toml|properties|json|xml|csv|"
    "log|logs|out|err|error|debug|trace|"
    "zip|tar|gz|bz2|7z|rar|war|jar|tgz|"
    "sh|bash|ps1|bat|cmd|pl|py|rb|cgi|"
    "php|asp|aspx|jsp|jspx|do|action|inc|"
    "doc|docx|pdf|pptx|txt|md"
)

CRITICAL_EXT = {
    '.env', '.env.local', '.env.production', '.env.backup', '.env.bak',
    '.sql', '.sql.gz', '.sql.bak', '.db', '.sqlite', '.sqlite3', '.dump',
    '.pem', '.crt', '.key', '.p12', '.pfx', '.jks',
    '.bak', '.backup', '.old', '.orig', '.save', '.tmp', '.swp',
    '.git', '.gitignore', '.gitconfig', '.git-credentials', '.svn',
    '.htpasswd', '.htaccess', '.htpasswd.bak', '.htaccess.bak',
    '.bash_history', '.zsh_history', '.mysql_history',
    '.npmrc', '.pypirc', '.netrc', '.pgpass',
    '.tfstate', '.tfvars', '.kubeconfig', '.dockerenv',
}

HIGH_EXT = {
    '.config', '.conf', '.cfg', '.ini', '.yaml', '.yml', '.toml', '.properties',
    '.json', '.xml', '.csv', '.log', '.logs', '.out', '.err', '.error', '.debug',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar', '.war', '.jar', '.tgz',
    '.sh', '.bash', '.ps1', '.bat', '.cmd', '.pl', '.py', '.rb', '.cgi',
    '.php', '.asp', '.aspx', '.jsp', '.jspx', '.do', '.action', '.inc',
}

MEDIUM_EXT = {'.txt', '.md', '.pdf', '.doc', '.docx', '.html', '.htm'}

ALL_EXT = CRITICAL_EXT | HIGH_EXT | MEDIUM_EXT

# ============================================================================
# CRITICAL FILES
# ============================================================================

CRITICAL_FILES = {
    '.git/config', '.git/HEAD', '.git-credentials', '.gitconfig',
    '.aws/credentials', '.aws/config', '.ssh/id_rsa', 'id_rsa', 'id_rsa.pub',
    '.htpasswd', '.htaccess', '.passwd', '.netrc', '.pgpass',
    'wp-config.php', 'wp-config.php.bak', 'configuration.php', 'config.php',
    '.env', '.env.local', '.env.production', '.env.backup',
    'docker-compose.yml', 'Dockerfile', 'terraform.tfstate', 'terraform.tfvars',
    'dump.sql', 'backup.sql', 'database.sql', 'db_backup.sql',
    'swagger.json', 'swagger.yaml', 'openapi.json', 'graphql',
    'actuator/health', 'actuator/env', 'actuator/heapdump',
    '.well-known/security.txt', 'security.txt', 'robots.txt',
    'phpinfo.php', 'info.php', 'adminer.php', 'phpmyadmin',
    'c99.php', 'r57.php', 'shell.php', 'cmd.php', 'wso.php',
}

# ============================================================================
# FILTER FUNCTIONS
# ============================================================================

def path_matches_wordlist(url):
    """
    Check if URL path matches any entry in SENSITIVE_PATHS
    O(1) set lookup - very fast even with 200K paths
    
    Returns: (matches: bool, matched_path: str or None)
    """
    if not SENSITIVE_PATHS:
        return False, None
    
    try:
        parsed = urlparse(url.lower())
        path = parsed.path.strip('/')
        
        if not path:
            return False, None
        
        # Full path match
        if path in SENSITIVE_PATHS:
            return True, path
        
        # Segment match
        segments = [s for s in path.split('/') if s]
        for segment in segments:
            if segment in SENSITIVE_PATHS:
                return True, segment
            if '.' in segment:
                base = segment.rsplit('.', 1)[0]
                if base in SENSITIVE_PATHS:
                    return True, base
        
        # Partial path
        for i in range(len(segments)):
            partial = '/'.join(segments[i:])
            if partial in SENSITIVE_PATHS:
                return True, partial
        
        return False, None
    except:
        return False, None


def is_sensitive(url):
    """
    Check if URL is sensitive
    
    Order:
    1. Extension match (fastest)
    2. CRITICAL_FILES match
    3. Wordlist path match
    
    Returns: (is_sensitive: bool, extension: str)
    """
    url_l = url.lower()
    path = url_l.split('?')[0]
    ext = ''
    fn = path.split('/')[-1]
    if '.' in fn:
        ext = '.' + fn.split('.')[-1]

    # Check 1: Extension
    if ext in ALL_EXT:
        return True, ext

    # Check 2: CRITICAL_FILES
    for cf in CRITICAL_FILES:
        if cf in url_l:
            return True, ext

    # Check 3: Wordlist
    matches, _ = path_matches_wordlist(url)
    if matches:
        return True, ext

    return False, ext


def calc_severity(url, ext, secrets=None):
    """Calculate severity score"""
    score = 0
    url_l = url.lower()
    
    if ext in CRITICAL_EXT:
        score = 8
    elif ext in HIGH_EXT:
        score = 5
    elif ext in MEDIUM_EXT:
        score = 3
    
    for cf in CRITICAL_FILES:
        if cf in url_l:
            score = 10
            break
    
    # Wordlist match scoring
    if score == 0:
        matches, _ = path_matches_wordlist(url)
        if matches:
            high_value = ['admin', 'backup', 'config', 'secret', 'password', 
                         'database', 'dump', 'sql', 'env', 'key', 'token', 'git']
            for kw in high_value:
                if kw in url_l:
                    score = 6
                    break
            if score == 0:
                score = 4
    
    if secrets:
        score += 5
    
    sev = 'critical' if score >= 8 else 'high' if score >= 5 else 'medium'
    return sev, min(score, 10)


def normalize_url(url):
    """Normalize URL for deduplication"""
    try:
        p = urlparse(url)
        host = p.netloc.lower().replace(':80', '').replace(':443', '')
        if host.startswith('www.'):
            host = host[4:]
        path = p.path.rstrip('/') or '/'
        return f"{p.scheme}://{host}{path}"
    except:
        return url.lower()
