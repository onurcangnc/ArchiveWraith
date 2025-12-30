# HistoryFinder (Temporal Recon v5.9)

A **100% stealth** web reconnaissance tool for finding sensitive documents in Wayback Machine. Makes **zero requests** to target servers.

## Table of Contents

- [Architecture](#architecture)
- [Design Patterns](#design-patterns)
- [Pipeline](#pipeline)
- [Features](#features)
- [File Structure](#file-structure)
- [Installation](#installation)
- [Deployment](#deployment)
- [Rate Limiting](#rate-limiting)
- [License](#license)

---

## Architecture

The application follows a **Layered Architecture** pattern with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                    Presentation Layer                    │
│                      (app.py - Flask)                    │
│  Routes, Authentication, Dashboard, Real-time updates   │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                     Service Layer                        │
│              (scanner.py + tools.py)                     │
│  Pipeline orchestration, External tools, CDX API        │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                      Data Layer                          │
│                    (database.py)                         │
│  PostgreSQL/ SQLite abstraction, Scan results           │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                    Utility Layer                         │
│              (filters.py + secrets.py)                   │
│  URL filtering, Secret detection, PDF analysis          │
└─────────────────────────────────────────────────────────┘
```

**Why Layered Architecture?**
- **Maintainability**: Each layer has a specific responsibility, making it easier to locate and fix bugs
- **Scalability**: Layers can be modified independently without affecting others
- **Testability**: Each layer can be tested in isolation
- **Flexibility**: Easy to swap implementations (e.g., SQLite → PostgreSQL)

---

## Design Patterns

### 1. Strategy Pattern

**Location:** `filters.py` - `is_sensitive()`, `calc_severity()`

**Purpose:** Encapsulates multiple filtering/scoring algorithms

**Why:**
- Different strategies for URL filtering (extension match, critical files, wordlist)
- Each strategy can be modified independently
- Easy to add new filtering strategies

```python
def is_sensitive(url):
    # Strategy 1: Extension match (fastest)
    if ext_pattern.search(url):
        return True, ext
    # Strategy 2: CRITICAL_FILES match
    if url.lower() in CRITICAL_FILES:
        return True, 'critical'
    # Strategy 3: Wordlist path match
    matches, _ = path_matches_wordlist(url)
    if matches:
        return True, 'wordlist'
```

### 2. Factory Pattern

**Location:** `tools.py:34-53` - `find_tool()`

**Purpose:** Encapsulates external tool discovery

**Why:**
- Abstracts the complexity of finding tool binaries across different systems
- Handles multiple search paths and Go installation locations
- Returns the appropriate tool path based on system configuration

```python
def find_tool(name, extra_paths=None):
    """Find tool binary - Factory for tool paths"""
    path = shutil.which(name)
    if path:
        return path

    # Try Go bin paths
    go_bins = [
        os.path.expanduser('~/go/bin/' + name),
        '/root/go/bin/' + name,
        '/usr/local/bin/' + name,
    ]
    for p in go_bins:
        if os.path.exists(p):
            return p
    return None
```

### 3. Repository Pattern

**Location:** `database.py` - `get_db()`, `update_scan()`, `save_findings()`

**Purpose:** Abstracts database operations behind a clean interface

**Why:**
- **Decoupling**: Business logic doesn't need to know database specifics
- **Flexibility**: Easy to switch between SQLite and PostgreSQL
- **Testability**: Can mock database operations for testing
- **Single Responsibility**: All database logic in one place

```python
def get_db():
    """Returns database connection based on configuration"""
    if USE_POSTGRES:
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(DB_PATH)
```

### 3. Observer Pattern

**Location:** Throughout the pipeline - `callback=msg` parameter

**Purpose:** Real-time progress reporting without tight coupling

**Why:**
- **Loose Coupling**: Scanner doesn't need to know about Flask routes
- **Real-time Updates**: UI can display scan progress without blocking
- **Extensibility**: Multiple listeners can subscribe to progress events
- **Separation of Concerns**: Progress logic separated from scanning logic

```python
def run_scan(scan_id, domain):
    def progress_callback(msg):
        update_scan(scan_id, step=msg)  # Notify observer

    urls, total_discovered_subdomains, error = fetch_cdx(domain, progress_callback)
```

### 4. Template Method Pattern

**Location:** `scanner.py` - `run_recon_pipeline()`

**Purpose:** Defines the skeleton of the scanning algorithm

**Why:**
- **Consistency**: Every scan follows the same steps
- **Flexibility**: Individual steps can be customized via callbacks
- **Code Reuse**: Common pipeline logic written once
- **Maintainability**: Changes to pipeline flow happen in one place

```python
def run_recon_pipeline(domain, callback=None):
    # Template: Fixed steps, customizable via callback
    subs_file, subs_count = run_subdomain_discovery(...)  # Step 1
    urls_file, urls_count = run_wayback_cdx(...)          # Step 2
    filtered = filter_urls(...)                             # Step 3
    return filtered, subs_count, None
```

### 5. Dependency Injection

**Location:** Function parameters throughout the codebase

**Purpose:** Pass dependencies (database, config, callbacks) as parameters

**Why:**
- **Testability**: Easy to inject mocks for testing
- **Flexibility**: Behavior can be changed at runtime
- **Decoupling**: Functions don't create their own dependencies
- **Clear Interfaces**: Function dependencies are explicit

```python
def run_scan(scan_id, domain):
    # callback dependency injected, not created internally
    def progress_callback(msg):
        update_scan(scan_id, step=msg)

    urls, total_discovered_subdomains, error = fetch_cdx(domain, progress_callback)
```

---

## Pipeline

```
1. Subdomain Discovery (subfinder + assetfinder)
   ↓
2. Wayback CDX API (parallel, rate-limited)
   ↓
3. Filtering (sensitive extensions + wordlist)
   ↓
4. Wayback Check (NO live requests to target)
```

---

## Features

- **100% Stealth**: Zero requests to target servers
- **Wayback CDX API**: Direct access to archived URLs
- **Rate Limiting**: Compliant with Wayback limits (1 req/s)
- **Secret Detection**: 19+ pattern types (AWS, GitHub, JWT, etc.)
- **PDF Analysis**: Deep content scanning for sensitive data
- **PostgreSQL + SQLite**: Flexible database backend
- **Real-time Progress**: Live updates via Server-Sent Events

---

## File Structure

```
HistoryFinder/
├── cli/                    # Command-line interface
│   ├── cli.py              # Main CLI entry point
│   └── __init__.py
├── web/                    # Flask web application
│   ├── app.py              # Web app routes, auth, dashboard
│   └── templates/          # Jinja2 HTML templates
│       ├── layout.html
│       ├── login.html
│       ├── dashboard.html
│       └── scan.html
├── core/                   # Shared business logic
│   ├── __init__.py         # Package exports
│   ├── scanner.py          # Scanning engine, Wayback integration
│   ├── tools.py            # External tools (subfinder, assetfinder, CDX API)
│   ├── filters.py          # URL filtering, severity calculation
│   ├── secrets.py          # Secret detection patterns
│   ├── config.py           # Configuration management
│   └── database.py         # Database abstraction layer
├── utils/                  # Helper modules
│   └── pdf_analyzer.py     # PDF deep analysis
├── data/                   # Static data files
│   └── wordlist.txt        # 197K+ sensitive paths
├── requirements.txt        # Python dependencies
├── .gitignore              # Git exclusions
└── README.md               # This file
```

**Why this structure?**
- **Separation of Concerns**: CLI and web app are completely separate
- **Shared Core**: Business logic in `core/` is reusable by both interfaces
- **Scalability**: Easy to add new interfaces (API, desktop app, etc.)
- **Clear Boundaries**: Each directory has a single purpose

---

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/HistoryFinder.git
cd HistoryFinder

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install external tools (Go)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomtomnom/assetfinder@latest

# Configure environment variables (optional)
export ADMIN_USER=admin
export ADMIN_PASS=your_secure_password
export DATABASE_URL=postgresql://user:pass@localhost/temporal_recon
export SECRET_KEY=your-secret-key-here
```

---

## Deployment

### Web Application

```bash
# Copy to server
scp -r HistoryFinder/* root@server:/opt/temportal-recon-web/

# SSH to server
ssh root@server

# Configure systemd service (if not already)
cat > /etc/systemd/system/temporal-recon.service << EOF
[Unit]
Description=Temporal Recon Web Application
After=network.target

[Service]
User=root
WorkingDirectory=/opt/temportal-recon-web
Environment="PATH=/root/go/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/usr/bin/python3 web/app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Restart service
systemctl daemon-reload
systemctl restart temporal-recon.service
systemctl enable temporal-recon.service
systemctl status temporal-recon.service
```

### CLI Usage

```bash
# Run full scan
python cli/cli.py scan example.com

# Subdomain discovery only
python cli/cli.py subdomains example.com

# Fetch Wayback URLs only
python cli/cli.py urls example.com

# Save results to file
python cli/cli.py scan example.com -o results.txt
```

---

## Rate Limiting

The tool respects Wayback Machine's official rate limits based on the [Python wayback library](https://wayback.readthedocs.io/en/latest/usage.html) documentation:

| API | Official Limit | Our Implementation |
|-----|---------------|-------------------|
| CDX Search | 0.8-1 req/s | `delay=2.0s`, `max_workers=2` (~1 req/s) |
| Memento | 8 req/s | Not used (Wayback API only) |

**Rate Limiting Features:**
- **14K domains** ~ **4 hours** (2 workers × 2s delay)
- **Exponential backoff** on 429/503 errors
- **Max retries: 3** per request with increasing delays
- **Per-request delay** after every CDX API call

**Retry Strategy:**
```python
# 429 (Too Many Requests): 5s, 10s, 15s backoff
# 503 (Service Unavailable): 3s, 6s, 9s backoff
# Timeout: 2s delay before retry
```

---

## License

MIT License - See LICENSE file for details
