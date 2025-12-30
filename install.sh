#!/bin/bash
# ============================================
# Temporal Recon - Full Installation Script
# PostgreSQL + Web App - Single Service Setup
# ============================================

set -e

echo "=========================================="
echo "  Temporal Recon - Full Installation"
echo "=========================================="

APP_DIR="/opt/temporal-recon-web"
DB_USER="temporal"
DB_PASS="temporal_secure_2025"
DB_NAME="temporal_recon"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ============================================
# 1. System Dependencies
# ============================================
echo -e "\n${YELLOW}[1/6] Installing system dependencies...${NC}"
apt update
apt install -y python3 python3-pip python3-venv postgresql postgresql-contrib curl wget git

# ============================================
# 2. PostgreSQL Setup
# ============================================
echo -e "\n${YELLOW}[2/6] Setting up PostgreSQL...${NC}"

# Start PostgreSQL
systemctl start postgresql
systemctl enable postgresql

# Create user and database
sudo -u postgres psql << EOSQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}') THEN
        CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';
    END IF;
END
\$\$;

SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')\gexec

GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
ALTER USER ${DB_USER} CREATEDB;
EOSQL

echo -e "${GREEN}[✓] PostgreSQL configured${NC}"

# ============================================
# 3. Go Tools (subfinder, waybackurls)
# ============================================
echo -e "\n${YELLOW}[3/6] Installing Go tools...${NC}"

if ! command -v go &> /dev/null; then
    wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    rm go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin:/root/go/bin
fi

export GOPATH=/root/go
export PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Install recon tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
go install -v github.com/tomnomnom/waybackurls@latest 2>/dev/null || true

echo -e "${GREEN}[✓] Go tools installed${NC}"

# ============================================
# 4. Python Environment
# ============================================
echo -e "\n${YELLOW}[4/6] Setting up Python environment...${NC}"

mkdir -p ${APP_DIR}
cd ${APP_DIR}

# Create venv if not exists
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install --upgrade pip
pip install flask requests gunicorn psycopg2-binary

echo -e "${GREEN}[✓] Python environment ready${NC}"

# ============================================
# 5. Systemd Service
# ============================================
echo -e "\n${YELLOW}[5/6] Creating systemd service...${NC}"

cat > /etc/systemd/system/temporal-recon.service << EOFSERVICE
[Unit]
Description=Temporal Recon Web Platform
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:/root/go/bin"
Environment="DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}"
Environment="ADMIN_USER=admin"
Environment="ADMIN_PASS=temporal2025"
ExecStart=${APP_DIR}/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 --threads 2 --timeout 600 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOFSERVICE

systemctl daemon-reload
echo -e "${GREEN}[✓] Systemd service created${NC}"

# ============================================
# 6. Start Service
# ============================================
echo -e "\n${YELLOW}[6/6] Starting service...${NC}"

systemctl enable temporal-recon
systemctl restart temporal-recon

sleep 2

if systemctl is-active --quiet temporal-recon; then
    echo -e "${GREEN}[✓] Service is running${NC}"
else
    echo -e "${YELLOW}[!] Service may need app.py - check logs${NC}"
fi

# ============================================
# Done
# ============================================
echo ""
echo "=========================================="
echo -e "${GREEN}  Installation Complete!${NC}"
echo "=========================================="
echo ""
echo "Database:"
echo "  postgresql://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}"
echo ""
echo "Web Interface:"
echo "  http://YOUR_IP:5000"
echo "  Username: admin"
echo "  Password: temporal2025"
echo ""
echo "Commands:"
echo "  systemctl status temporal-recon"
echo "  journalctl -u temporal-recon -f"
echo ""
echo "Next: Copy app.py and templates/ to ${APP_DIR}"
