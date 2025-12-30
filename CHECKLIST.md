# Deployment Checklist

## Pre-Deployment ✅

- [ ] **Code Review**
  - [x] Parallel processing implemented (GAU: 4 workers, httpx: 3 batches)
  - [x] Rate limiting protection (GAU: 0.2s/domain, Wayback: 1s/10 req)
  - [x] Zero timeout approach (max coverage)
  - [x] Optimized worker count (50 workers, 3s timeout)
  - [x] Linux-only paths (no Windows dependencies)

- [ ] **Files to Upload**
  - [x] app.py
  - [x] scanner.py
  - [x] tools.py
  - [x] filters.py
  - [x] secrets.py
  - [x] config.py
  - [x] database.py
  - [x] wordlist.txt (197,534 paths)
  - [x] templates/ directory
  - [ ] DEPLOYMENT.md (this file)
  - [ ] README.md (if exists)

- [ ] **Files to Exclude**
  - [ ] venv/ (will create on server)
  - [ ] __pycache__/
  - [ ] *.pyc
  - [ ] temporal_recon.db (will create on server)
  - [ ] .git/ (if using git)

---

## Server Setup 🚀

### Step 1: System Preparation
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv golang-go git

# Create user (optional, for security)
sudo useradd -m -s /bin/bash recon
sudo su - recon
```

### Step 2: Install Go Tools
```bash
# Install Go tools
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/d3mondev/puredns/v2@latest

# Add to PATH
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify installation
which gau httpx subfinder puredns
```

### Step 3: Upload Application
```bash
# On your local machine
cd c:\Users\rekal\OneDrive\Belgeler\Projects\HistoryFinder

# Using SCP
scp -r app.py scanner.py tools.py filters.py secrets.py config.py database.py wordlist.txt templates/ user@server:/home/recon/HistoryFinder/

# Or using rsync (faster, excludes unnecessary files)
rsync -avz --exclude 'venv' --exclude '__pycache__' --exclude '*.pyc' --exclude '*.db' \
  HistoryFinder/ user@server:/home/recon/HistoryFinder/
```

### Step 4: Python Setup
```bash
# SSH into server
ssh user@server
cd /home/recon/HistoryFinder

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install flask requests urllib3 gunicorn

# Verify Python installation
python --version
pip list | grep -E 'flask|requests|urllib3'
```

### Step 5: Test Run
```bash
# Start application (development mode)
python app.py

# Check if running
curl http://localhost:5000

# Check logs
# Should see: "Running on http://127.0.0.1:5000"
```

---

## Production Deployment 🚀

### Option A: Systemd Service (Recommended)

```bash
# Create service file
sudo nano /etc/systemd/system/historyfinder.service
```

Paste this:
```ini
[Unit]
Description=HistoryFinder Web Recon
After=network.target

[Service]
Type=simple
User=recon
WorkingDirectory=/home/recon/HistoryFinder
Environment="PATH=/home/recon/HistoryFinder/venv/bin:/usr/local/bin:/home/recon/go/bin"
ExecStart=/home/recon/HistoryFinder/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable historyfinder
sudo systemctl start historyfinder
sudo systemctl status historyfinder
```

### Option B: Nginx Reverse Proxy (Optional)

```bash
# Install Nginx
sudo apt install -y nginx

# Create config
sudo nano /etc/nginx/sites-available/historyfinder
```

Paste this:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable:
```bash
sudo ln -s /etc/nginx/sites-available/historyfinder /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Post-Deployment Tests ✅

### Test 1: Tool Verification
```bash
# Test each tool
~/go/bin/gau --version
~/go/bin/httpx -version
~/go/bin/subfinder -version
~/go/bin/puredns --version
```

### Test 2: Small Domain Scan
- [ ] Login to web interface
- [ ] Start scan with small domain (e.g., example.com)
- [ ] Verify all 5 steps complete:
  - [ ] [1/5] Subdomain discovery
  - [ ] [2/5] puredns resolution
  - [ ] [3/5] httpx live check
  - [ ] [4/5] gau URL collection
  - [ ] [5/5] Filtering URLs
- [ ] Check findings table populated

### Test 3: Performance Check
- [ ] Monitor CPU usage (should use multiple cores)
- [ ] Monitor RAM usage (should be < 4GB for 1000 domains)
- [ ] Check scan time:
  - 50 subs: < 2 min
  - 200 subs: < 8 min
  - 1000 subs: < 20 min

### Test 4: Rate Limiting
- [ ] No "429 Too Many Requests" errors
- [ ] No IP bans from external services
- [ ] Smooth progress updates

---

## Monitoring & Maintenance 📊

### Log Files
```bash
# Application logs
sudo journalctl -u historyfinder -f

# Nginx logs (if using)
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### Performance Monitoring
```bash
# CPU and RAM
htop

# Disk usage
df -h

# Process info
ps aux | grep gunicorn
```

### Database Backup
```bash
# Backup
cp temporal_recon.db temporal_recon.db.backup.$(date +%Y%m%d)

# Automated backup (add to crontab)
0 2 * * * cp /home/recon/HistoryFinder/temporal_recon.db /backups/db_$(date +\%Y\%m\%d).db
```

---

## Troubleshooting 🔧

### Issue: Tools not found
**Solution:**
```bash
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
```

### Issue: Permission denied
**Solution:**
```bash
chmod +x ~/go/bin/*
```

### Issue: Port 5000 in use
**Solution:**
```bash
lsof -i :5000
sudo kill -9 <PID>
# Or change port in app.py
```

### Issue: Out of memory
**Solution:**
```bash
# Reduce workers in config.py
export LIVE_CHECK_WORKERS=25
export LIVE_CHECK_TIMEOUT=5
```

### Issue: Slow scans
**Solution:**
```bash
# Check CPU cores
nproc

# Increase workers if you have more cores
export LIVE_CHECK_WORKERS=100
```

---

## Security 🔒

- [ ] Change default credentials (admin/temporal2025)
- [ ] Use HTTPS (Let's Encrypt with Nginx)
- [ ] Firewall configuration (UFW)
- [ ] Regular updates
- [ ] Monitor access logs

---

## Completed ✅

- [x] Code optimized for Linux
- [x] Windows files removed
- [x] Deployment guide created
- [x] Checklist prepared

**Ready to transfer!** 🚀

---

**Quick Deploy Command:**
```bash
# ONE-LINE DEPLOY (run on server)
cd ~ && mkdir -p HistoryFinder && cd HistoryFinder && python3 -m venv venv && source venv/bin/activate && pip install flask requests urllib3 gunicorn && echo "Ready for files transfer"
```
