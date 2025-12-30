"""
ArchiveWraith - Database Operations
"""
import sqlite3
from .config import DATABASE_URL, USE_POSTGRES, DB_PATH, DEFAULT_USER, DEFAULT_PASS_HASH

# PostgreSQL pool
pg_pool = None
if USE_POSTGRES:
    try:
        import psycopg2
        from psycopg2 import pool
        pg_pool = pool.ThreadedConnectionPool(2, 20, DATABASE_URL)
        print(f"[✓] PostgreSQL connected")
    except Exception as e:
        print(f"[!] PostgreSQL failed: {e}")

def init_db():
    """Initialize database tables"""
    if USE_POSTGRES and pg_pool:
        _init_postgres()
    else:
        _init_sqlite()

def _init_postgres():
    conn = pg_pool.getconn()
    try:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY, domain TEXT, status TEXT DEFAULT 'pending',
            step TEXT DEFAULT 'starting', progress_percent INTEGER DEFAULT 0,
            total_urls INTEGER DEFAULT 0, sensitive_urls INTEGER DEFAULT 0,
            checked_urls INTEGER DEFAULT 0, live_urls INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0, critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0, medium_count INTEGER DEFAULT 0,
            recovered_count INTEGER DEFAULT 0, secrets_count INTEGER DEFAULT 0,
            unique_subdomains INTEGER DEFAULT 0, urls_per_sec INTEGER DEFAULT 0,
            eta_seconds INTEGER DEFAULT 0, error_message TEXT,
            started_at TIMESTAMP, completed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS findings (
            id SERIAL PRIMARY KEY, scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
            subdomain TEXT, url TEXT, url_normalized TEXT, severity TEXT,
            extension TEXT, score INTEGER DEFAULT 0, status_code INTEGER,
            secrets_found TEXT, secrets_preview TEXT, recovered INTEGER DEFAULT 0,
            found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)')
        c.execute("SELECT * FROM users WHERE username = %s", (DEFAULT_USER,))
        if not c.fetchone():
            c.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                      (DEFAULT_USER, DEFAULT_PASS_HASH))
        conn.commit()
        print("[✓] PostgreSQL initialized")
    finally:
        pg_pool.putconn(conn)

def _init_sqlite():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY, domain TEXT, status TEXT DEFAULT 'pending',
        step TEXT DEFAULT 'starting', progress_percent INTEGER DEFAULT 0,
        total_urls INTEGER DEFAULT 0, sensitive_urls INTEGER DEFAULT 0,
        checked_urls INTEGER DEFAULT 0, live_urls INTEGER DEFAULT 0,
        total_findings INTEGER DEFAULT 0, critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0, medium_count INTEGER DEFAULT 0,
        recovered_count INTEGER DEFAULT 0, secrets_count INTEGER DEFAULT 0,
        unique_subdomains INTEGER DEFAULT 0, urls_per_sec INTEGER DEFAULT 0,
        eta_seconds INTEGER DEFAULT 0, error_message TEXT,
        started_at TIMESTAMP, completed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY, scan_id INTEGER, subdomain TEXT, url TEXT,
        url_normalized TEXT, severity TEXT, extension TEXT, score INTEGER DEFAULT 0,
        status_code INTEGER, secrets_found TEXT, secrets_preview TEXT,
        recovered INTEGER DEFAULT 0, found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(id))''')
    c.execute("SELECT * FROM users WHERE username = ?", (DEFAULT_USER,))
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                  (DEFAULT_USER, DEFAULT_PASS_HASH))
    conn.commit()
    conn.close()
    print("[✓] SQLite initialized")

def get_db():
    """Get database connection"""
    if USE_POSTGRES and pg_pool:
        return PostgresConnection()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

class PostgresConnection:
    def __init__(self):
        self.conn = pg_pool.getconn()
        self.conn.autocommit = False
    def execute(self, query, params=None):
        query = query.replace('?', '%s')
        cursor = self.conn.cursor()
        cursor.execute(query, params or ())
        return PostgresCursor(cursor)
    def commit(self):
        self.conn.commit()
    def close(self):
        pg_pool.putconn(self.conn)

class PostgresCursor:
    def __init__(self, cursor):
        self.cursor = cursor
    def fetchone(self):
        row = self.cursor.fetchone()
        if not row: return None
        cols = [d[0] for d in self.cursor.description]
        return DictRow(dict(zip(cols, row)))
    def fetchall(self):
        rows = self.cursor.fetchall()
        cols = [d[0] for d in self.cursor.description]
        return [DictRow(dict(zip(cols, r))) for r in rows]
    @property
    def lastrowid(self):
        return None

class DictRow(dict):
    def __getattr__(self, k):
        try: return self[k]
        except KeyError: raise AttributeError(k)
    def __getitem__(self, k):
        if isinstance(k, int): return list(self.values())[k]
        return super().__getitem__(k)

def update_scan(scan_id, **kwargs):
    """Update scan record"""
    conn = get_db()
    sets = ','.join(f"{k}=?" for k in kwargs)
    vals = list(kwargs.values()) + [scan_id]
    conn.execute(f"UPDATE scans SET {sets} WHERE id=?", vals)
    conn.commit()
    conn.close()
