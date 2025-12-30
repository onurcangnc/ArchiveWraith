"""
Temporal Recon v5.9 - Secret Detection
"""
import re

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret": re.compile(r"(?:aws)?_?(?:secret)?_?(?:access)?_?key.{0,20}['\"][0-9a-zA-Z/+=]{40}['\"]", re.I),
    "GitHub Token": re.compile(r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})"),
    "GitLab Token": re.compile(r"glpat-[a-zA-Z0-9\-]{20,}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack Token": re.compile(r"xox[pboa]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", re.I),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"),
    "Stripe Key": re.compile(r"(sk|rk)_(live|test)_[0-9a-zA-Z]{24,}"),
    "JWT Token": re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Bearer Token": re.compile(r"[Bb]earer\s+[a-zA-Z0-9_\-\.=]{20,}"),
    "Basic Auth": re.compile(r"[Bb]asic\s+[a-zA-Z0-9+/=]{20,}"),
    "Password Field": re.compile(r"['\"]?(?:password|passwd|pwd|secret)['\"]?\s*[:=]\s*['\"]([^'\"]{4,})['\"]", re.I),
    "API Key Generic": re.compile(r"['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?", re.I),
    "Database URL": re.compile(r"(mysql|postgres|postgresql|mongodb|redis)://[^\s\"'<>]+"),
    "Discord Webhook": re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+"),
    "Telegram Bot": re.compile(r"[0-9]{8,10}:AA[0-9A-Za-z\-_]{33}"),
    "SendGrid Key": re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
    "Twilio Key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "Firebase URL": re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
    "NPM Token": re.compile(r"npm_[A-Za-z0-9]{36}"),
}

def check_secrets(content):
    """Check content for secrets, return list of found types"""
    return [name for name, pattern in SECRET_PATTERNS.items() if pattern.search(content)]

PDF_SENSITIVE_WORDS = [
    'internal use only', 'confidential', 'strictly private', 'personal & confidential',
    'private', 'restricted', 'internal', 'not for distribution', 'proprietary',
    'trade secret', 'classified', 'sensitive', 'bank statement', 'invoice',
    'salary', 'contract', 'agreement', 'non disclosure', 'passport', 'ssn',
    'credit card', 'password', 'api key',
]
