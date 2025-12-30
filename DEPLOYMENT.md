# HistoryFinder Deployment Guide

## Server Requirements

**Minimum:**
- Linux (Ubuntu/Debian/Kali/RHEL)
- 2 CPU cores
- 4 GB RAM
- 10 GB disk space

**Recommended:**
- 4+ CPU cores (for parallel processing)
- 8 GB RAM
- 20 GB disk space

---

## Installation Steps

### 1. Install Go Tools

```bash
# Install Go (if not installed)
sudo apt update
sudo apt install -y golang-go

# Install reconnaissance tools
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/d3mondev/puredns/v2@latest

# Add Go bin to PATH (add to ~/.bashrc)
export PATH=$PATH:~/go/bin
source ~/.bashrc
```

### 2. Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install flask requests urllib3
```

### 3. Upload Files

```bash
# On local machine (Windows)
scp -r HistoryFinder/* user@remote-server:/path/to/app/

# Or using rsync
rsync -avz --exclude 'venv' --exclude '*.pyc' HistoryFinder/ user@server:/path/to/app/
```

### 4. Configure & Run

```bash
# On remote server
cd /path/to/app
source venv/bin/activate

# Production server with gunicorn (recommended)
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Or development server (for testing)
python app.py
```

---

## Configuration (Optional)

Environment variables:

```bash
# Performance tuning
export LIVE_CHECK_WORKERS=50  # Concurrent URL checks (default: 50)
export LIVE_CHECK_TIMEOUT=3    # HTTP timeout in seconds (default: 3)

# Authentication
export ADMIN_USER=your_username
export ADMIN_PASS=your_password
export SECRET_KEY=your_secret_key

# Database
export DATABASE_URL=postgresql://user:pass@localhost/dbname
```

---

## Performance Expectations

**Parallel Processing Speedup:**
- GAU: 4x faster (4 parallel processes)
- httpx: 3x faster (3 parallel batches)
- Live check: 1.67x faster (50 workers)

**Typical Scan Times:**
- 50 subdomains: ~2 minutes
- 200 subdomains: ~8 minutes
- 1000 subdomains: ~15-20 minutes

---

## Systemd Service (Optional)

Create `/etc/systemd/system/historyfinder.service`:

```ini
[Unit]
Description=HistoryFinder Web Recon
After=network.target

[Service]
Type=simple
User=your_user
WorkingDirectory=/path/to/HistoryFinder
Environment="PATH=/path/to/HistoryFinder/venv/bin:/usr/local/bin:/home/your_user/go/bin"
ExecStart=/path/to/HistoryFinder/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable historyfinder
sudo systemctl start historyfinder
sudo systemctl status historyfinder
```

---

## Nginx Reverse Proxy (Optional)

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

---

## Troubleshooting

**Tools not found:**
```bash
which gau httpx subfinder puredns
# Should show paths like: ~/go/bin/gau
```

**Permission denied:**
```bash
chmod +x ~/go/bin/*
```

**Port 5000 already in use:**
```bash
# Change port in app.py or kill existing process
lsof -i :5000
kill -9 <PID>
```

---

## Files Structure

```
HistoryFinder/
├── app.py              # Flask application
├── scanner.py          # Scan worker
├── tools.py            # External tool integration
├── filters.py          # URL filtering logic
├── secrets.py          # Secret detection
├── config.py           # Configuration
├── database.py         # Database operations
├── wordlist.txt        # 197K sensitive paths
├── templates/          # HTML templates
│   ├── login.html
│   ├── dashboard.html
│   └── scan.html
├── venv/               # Python virtual env
└── temporal_recon.db   # SQLite database (created automatically)
```

---

**Ready for deployment!** 🚀
