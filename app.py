#!/usr/bin/env python3
"""
Temporal Recon v5.8 - Smart Recon & Recovery Platform
======================================================
Features:
- Server-side severity filtering
- PDF filtering (only show PDFs with secrets)
- Port normalization in subdomain stats
- PDF Deep Analysis with progress tracking
"""
import os
import sys
import json
import hashlib
import threading
import time
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response

sys.stdout = sys.__stdout__
sys.stderr = sys.__stderr__
os.environ['PYTHONUNBUFFERED'] = '1'

_print = print
def print(*args, **kwargs):
    kwargs['flush'] = True
    _print(*args, **kwargs)

from config import SECRET_KEY, DEFAULT_USER, DEFAULT_PASS_HASH, USE_POSTGRES
from database import init_db, get_db
from filters import SENSITIVE_PATHS
from scanner import run_scan

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Low-value extensions - only show if they have secrets
LOW_VALUE_EXTENSIONS = {'.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.odt', '.ods', '.odp'}

# PDF analysis state (in-memory for simplicity)
pdf_analysis_state = {}

# ============================================================================
# AUTH
# ============================================================================

def login_required(f):
    @wraps(f)
    def dec(*a, **k):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*a, **k)
    return dec

# ============================================================================
# HELPERS
# ============================================================================

def normalize_subdomain(subdomain):
    """Remove default ports from subdomain for grouping"""
    if not subdomain:
        return subdomain
    if subdomain.endswith(':80'):
        return subdomain[:-3]
    if subdomain.endswith(':443'):
        return subdomain[:-4]
    return subdomain

def build_filter_conditions(scan_id, selected_subdomain, search_query, severity_filter):
    """Build SQL WHERE conditions and parameters"""
    conditions = ["scan_id = ?"]
    params = [scan_id]
    
    if selected_subdomain:
        conditions.append("(subdomain = ? OR subdomain = ? OR subdomain = ?)")
        params.extend([selected_subdomain, f"{selected_subdomain}:80", f"{selected_subdomain}:443"])
    
    if search_query:
        conditions.append("url LIKE ?")
        params.append(f"%{search_query}%")
    
    if severity_filter == 'critical':
        conditions.append("severity = 'critical'")
    elif severity_filter == 'high':
        conditions.append("severity = 'high'")
    elif severity_filter == 'medium':
        conditions.append("severity = 'medium'")
    elif severity_filter == 'recovered':
        conditions.append("recovered = 1")
    elif severity_filter == 'secrets':
        conditions.append("secrets_found IS NOT NULL AND secrets_found != ''")
    
    ext_list = list(LOW_VALUE_EXTENSIONS)
    ext_placeholders = ','.join(['?' for _ in ext_list])
    conditions.append(f"""
        (extension IS NULL 
         OR extension NOT IN ({ext_placeholders}) 
         OR (extension IN ({ext_placeholders}) AND secrets_found IS NOT NULL AND secrets_found != ''))
    """)
    params.extend(ext_list)
    params.extend(ext_list)
    
    return " AND ".join(conditions), params

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = hashlib.sha256(request.form.get('password', '').encode()).hexdigest()
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=? AND password_hash=?", (u, p)).fetchone()
        conn.close()
        if user:
            session['user'] = u
            return redirect('/')
        error = "Invalid credentials"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/')
@login_required
def dashboard():
    conn = get_db()
    scans = conn.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    return render_template('dashboard.html', scans=scans)

@app.route('/scan/new', methods=['POST'])
@login_required
def new_scan():
    domain = request.form.get('domain', '').strip().lower()
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    if not domain:
        return redirect('/')

    conn = get_db()
    existing = conn.execute("SELECT id FROM scans WHERE status='running'").fetchone()
    if existing:
        conn.close()
        return redirect(f'/scan/{existing["id"]}')

    if USE_POSTGRES:
        cur = conn.execute("INSERT INTO scans (domain, status) VALUES (%s, 'pending') RETURNING id", (domain,))
        scan_id = cur.fetchone()['id']
    else:
        conn.execute("INSERT INTO scans (domain, status) VALUES (?, 'pending')", (domain,))
        conn.commit()
        scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    conn.commit()
    conn.close()

    t = threading.Thread(target=run_scan, args=(scan_id, domain))
    t.daemon = True
    t.start()

    return redirect(f'/scan/{scan_id}')

@app.route('/scan/<int:scan_id>')
@login_required
def view_scan(scan_id):
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return "Not found", 404

    # Get PDF count for deep scan button
    pdf_count = conn.execute("""
        SELECT COUNT(*) FROM findings 
        WHERE scan_id = ? AND extension = '.pdf'
          AND (secrets_found IS NULL OR secrets_found = '')
    """, (scan_id,)).fetchone()[0]

    ext_list = list(LOW_VALUE_EXTENSIONS)
    ext_placeholders = ','.join(['?' for _ in ext_list])
    
    raw_stats = conn.execute(f"""
        SELECT subdomain,
               COUNT(*) as total,
               SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
               SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
               SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) as medium,
               SUM(CASE WHEN recovered=1 THEN 1 ELSE 0 END) as recovered,
               SUM(CASE WHEN secrets_found IS NOT NULL AND secrets_found != '' THEN 1 ELSE 0 END) as secrets
        FROM findings 
        WHERE scan_id=? 
          AND (extension IS NULL 
               OR extension NOT IN ({ext_placeholders}) 
               OR (extension IN ({ext_placeholders}) AND secrets_found IS NOT NULL AND secrets_found != ''))
        GROUP BY subdomain
    """, [scan_id] + ext_list + ext_list).fetchall()
    
    merged_stats = {}
    for row in raw_stats:
        normalized = normalize_subdomain(row['subdomain'])
        if normalized not in merged_stats:
            merged_stats[normalized] = {
                'subdomain': normalized,
                'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'recovered': 0, 'secrets': 0
            }
        merged_stats[normalized]['total'] += row['total']
        merged_stats[normalized]['critical'] += row['critical']
        merged_stats[normalized]['high'] += row['high']
        merged_stats[normalized]['medium'] += row['medium']
        merged_stats[normalized]['recovered'] += row['recovered']
        merged_stats[normalized]['secrets'] += row['secrets']
    
    subdomain_stats = sorted(merged_stats.values(), 
                            key=lambda x: (x['critical'], x['high'], x['total']), 
                            reverse=True)

    selected_subdomain = request.args.get('subdomain', None)
    search_query = request.args.get('q', '').strip()
    severity_filter = request.args.get('severity', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 100

    where_clause, params = build_filter_conditions(scan_id, selected_subdomain, search_query, severity_filter)
    
    total = conn.execute(f"SELECT COUNT(*) FROM findings WHERE {where_clause}", params).fetchone()[0]
    
    findings = conn.execute(f"""
        SELECT * FROM findings WHERE {where_clause}
        ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END, score DESC
        LIMIT ? OFFSET ?
    """, params + [per_page, (page-1)*per_page]).fetchall()

    total_pages = (total + per_page - 1) // per_page
    conn.close()

    return render_template('scan.html', scan=scan, findings=findings, subdomain_stats=subdomain_stats,
                          selected_subdomain=selected_subdomain, search_query=search_query,
                          severity_filter=severity_filter, pdf_count=pdf_count,
                          page=page, total_pages=total_pages, total_results=total)

@app.route('/scan/<int:scan_id>/pdf-analyze', methods=['POST'])
@login_required
def pdf_analyze(scan_id):
    """Trigger PDF deep analysis for a scan"""
    global pdf_analysis_state
    
    try:
        from pdf_analyzer import run_pdf_analysis
        
        # Initialize state
        pdf_analysis_state[scan_id] = {
            'status': 'running',
            'total': 0,
            'analyzed': 0,
            'secrets_found': 0,
            'current_url': ''
        }
        
        def run_with_callback():
            global pdf_analysis_state
            
            def progress_callback(analyzed, total, secrets_found, current_url=''):
                pdf_analysis_state[scan_id] = {
                    'status': 'running',
                    'total': total,
                    'analyzed': analyzed,
                    'secrets_found': secrets_found,
                    'current_url': current_url[:60] + '...' if len(current_url) > 60 else current_url
                }
            
            secrets = run_pdf_analysis(scan_id, progress_callback)
            
            pdf_analysis_state[scan_id] = {
                'status': 'completed',
                'total': pdf_analysis_state[scan_id].get('total', 0),
                'analyzed': pdf_analysis_state[scan_id].get('total', 0),
                'secrets_found': secrets,
                'current_url': ''
            }
        
        thread = threading.Thread(target=run_with_callback)
        thread.daemon = True
        thread.start()
        
        return jsonify({'status': 'started', 'message': 'PDF analysis started'})
    except ImportError:
        return jsonify({'status': 'error', 'message': 'PDF analyzer not available. Install pdfplumber: pip install pdfplumber'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/scan/<int:scan_id>/pdf-status')
@login_required
def pdf_status(scan_id):
    """Get PDF analysis progress"""
    global pdf_analysis_state
    
    if scan_id in pdf_analysis_state:
        return jsonify(pdf_analysis_state[scan_id])
    else:
        return jsonify({'status': 'idle', 'total': 0, 'analyzed': 0, 'secrets_found': 0})

@app.route('/scan/<int:scan_id>/stream')
@login_required
def scan_stream(scan_id):
    def gen():
        while True:
            conn = get_db()
            scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            conn.close()
            if not scan:
                break

            progress = 0
            if scan['sensitive_urls'] and scan['sensitive_urls'] > 0:
                progress = int((scan['checked_urls'] or 0) * 100 / scan['sensitive_urls'])

            rate = scan['urls_per_sec'] or 0
            eta = '--'
            if rate > 0:
                remaining = (scan['sensitive_urls'] or 0) - (scan['checked_urls'] or 0)
                eta_sec = remaining // rate if rate > 0 else 0
                if eta_sec < 60:
                    eta = f"{eta_sec}s"
                elif eta_sec < 3600:
                    eta = f"{eta_sec//60}m {eta_sec%60}s"
                else:
                    eta = f"{eta_sec//3600}h"

            data = {
                'status': scan['status'], 'step': scan['step'] or '',
                'progress': progress, 'total_urls': scan['total_urls'] or 0,
                'sensitive': scan['sensitive_urls'] or 0, 'checked': scan['checked_urls'] or 0,
                'live': scan['live_urls'] or 0, 'critical': scan['critical_count'] or 0,
                'high': scan['high_count'] or 0, 'medium': scan['medium_count'] or 0,
                'recovered': scan['recovered_count'] or 0, 'secrets': scan['secrets_count'] or 0,
                'rate': rate, 'eta': eta, 'subdomains': scan['unique_subdomains'] or 0,
                'findings': scan['total_findings'] or 0,
            }
            yield f"data: {json.dumps(data)}\n\n"

            if scan['status'] in ('completed', 'error'):
                break
            time.sleep(1)

    return Response(gen(), mimetype='text/event-stream',
                   headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    conn = get_db()
    conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
    conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()
    return redirect('/')

# ============================================================================
# MAIN
# ============================================================================

init_db()

if __name__ == '__main__':
    print("\n" + "="*60)
    print("Temporal Recon v5.8 - Smart Recon & Recovery Platform")
    print("="*60)
    print(f"[*] Database: {'PostgreSQL' if USE_POSTGRES else 'SQLite'}")
    print(f"[*] Wordlist: {len(SENSITIVE_PATHS):,} paths")
    print(f"[*] Low-value extensions filtered: {', '.join(LOW_VALUE_EXTENSIONS)}")
    print("="*60 + "\n")

    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
