#!/bin/bash
# Reset PostgreSQL Database for Temporal Recon

echo "=== Resetting Temporal Recon Database ==="

sudo -u postgres psql -d temporal_recon << 'EOF'
-- Drop tables and recreate without foreign key
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    domain TEXT,
    status TEXT DEFAULT 'pending',
    total_subdomains INTEGER DEFAULT 0,
    processed_subdomains INTEGER DEFAULT 0,
    total_urls INTEGER DEFAULT 0,
    checked_urls INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER,
    subdomain TEXT,
    url TEXT,
    url_normalized TEXT,
    severity TEXT,
    extension TEXT,
    score INTEGER DEFAULT 0,
    secrets_found TEXT,
    recovered INTEGER DEFAULT 0,
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_score ON findings(score DESC);
CREATE INDEX idx_findings_url_normalized ON findings(url_normalized);
CREATE INDEX idx_scans_status ON scans(status);

-- Create default admin user (password: temporal2025)
INSERT INTO users (username, password_hash) 
VALUES ('admin', '5e884898da28047d91956c1da6f56f22b8a4d46cb5cdb8f22e1c5f0c4898be95');

SELECT 'Tables recreated successfully!' as status;
EOF

echo ""
echo "✅ Database reset complete!"
echo "   Username: admin"
echo "   Password: temporal2025"
echo ""
echo "Restarting service..."
sudo systemctl restart temporal-recon
echo "✅ Done!"
