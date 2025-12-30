"""
ArchiveWraith - PDF Deep Analyzer
==================================
Analyzes PDF content for sensitive keywords (Turkish + English)
Runs asynchronously after main scan completes

Features:
- Stream-based processing (no disk writes)
- Parallel analysis with ThreadPoolExecutor
- Turkish + English keyword detection
- Progress callback support
- Auto-updates findings in database
"""
import io
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
import urllib3
urllib3.disable_warnings()

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import get_db, update_scan
from core.secrets import check_secrets

# Try to import PDF libraries
try:
    import pdfplumber
    PDF_LIBRARY = 'pdfplumber'
except ImportError:
    try:
        from pdfminer.high_level import extract_text as pdfminer_extract
        PDF_LIBRARY = 'pdfminer'
    except ImportError:
        PDF_LIBRARY = None

# Sensitive keywords - English + Turkish
PDF_SENSITIVE_KEYWORDS = [
    # English - Classification
    'confidential', 'internal use only', 'strictly private', 'private & confidential',
    'restricted', 'not for distribution', 'do not share', 'proprietary',
    'trade secret', 'classified', 'sensitive', 'staff only', 'management only',
    'internal only', 'company confidential', 'secret',
    
    # English - Financial
    'bank statement', 'invoice', 'salary', 'payroll', 'bank account',
    'credit card', 'debit card', 'account number', 'routing number',
    'tax return', 'financial statement', 'balance sheet', 'income statement',
    
    # English - Legal/Contract
    'contract', 'agreement', 'non disclosure', 'nda', 'memorandum',
    'terms and conditions', 'license agreement', 'settlement',
    
    # English - Personal/Identity
    'passport', 'social security', 'ssn', 'date of birth', 'identity',
    'driver license', 'id number', 'national id', 'birth certificate',
    
    # English - Credentials
    'password', 'credential', 'api key', 'secret key', 'private key',
    'access token', 'auth token', 'bearer token', 'jwt', 'oauth',
    'username', 'login', 'authentication',
    
    # English - Technical
    'database', 'connection string', 'jdbc', 'mongodb', 'mysql',
    'postgresql', 'redis', 'aws_access', 'aws_secret', 'azure',
    
    # Türkçe - Gizlilik Sınıflandırması
    'gizli', 'çok gizli', 'hizmete özel', 'kişiye özel', 'kurum içi',
    'dağıtılamaz', 'paylaşılamaz', 'ticari sır', 'özel', 'yasak',
    'yayınlanamaz', 'kopyalanamaz', 'gizlilik dereceli',
    
    # Türkçe - Finansal
    'banka hesap', 'hesap özeti', 'maaş', 'bordro', 'ücret',
    'kredi kartı', 'banka kartı', 'hesap numarası', 'iban',
    'vergi', 'kdv', 'fatura', 'bilanço', 'gelir tablosu', 'mali rapor',
    
    # Türkçe - Hukuki/Sözleşme
    'sözleşme', 'mukavele', 'anlaşma', 'protokol', 'taahhütname',
    'gizlilik anlaşması', 'iş sözleşmesi', 'kira sözleşmesi',
    
    # Türkçe - Kişisel/Kimlik
    'kimlik', 'tc kimlik', 'tckn', 'ehliyet', 'pasaport', 'nüfus',
    'doğum tarihi', 'anne kızlık', 'ikametgah', 'adres',
    
    # Türkçe - Kurumsal
    'yönetim kurulu', 'iç denetim', 'teftiş', 'soruşturma',
    'disiplin', 'personel', 'özlük', 'sicil', 'performans',
    'ihale', 'teklif', 'fiyat listesi', 'müşteri listesi',
    'tedarikçi', 'bayii', 'distribütör',
    
    # Türkçe - Credentials
    'şifre', 'parola', 'kullanıcı adı', 'giriş bilgileri',
]

# Compile regex pattern for faster matching
KEYWORD_PATTERN = re.compile(
    '|'.join(re.escape(kw) for kw in PDF_SENSITIVE_KEYWORDS),
    re.IGNORECASE
)


def extract_text_from_pdf(pdf_bytes):
    """Extract text from PDF bytes using available library"""
    if PDF_LIBRARY == 'pdfplumber':
        try:
            with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
                text_parts = []
                for page in pdf.pages[:20]:  # Max 20 pages
                    text = page.extract_text()
                    if text:
                        text_parts.append(text)
                return '\n'.join(text_parts)
        except Exception as e:
            return None
    
    elif PDF_LIBRARY == 'pdfminer':
        try:
            return pdfminer_extract(io.BytesIO(pdf_bytes))
        except Exception as e:
            return None
    
    return None


def find_sensitive_keywords(text):
    """Find sensitive keywords in text, return list of found keywords"""
    if not text:
        return []
    
    matches = KEYWORD_PATTERN.findall(text.lower())
    return list(set(matches))


def analyze_pdf_url(url, timeout=30):
    """
    Download and analyze a single PDF URL
    Returns: (success, keywords_found, preview)
    """
    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=False,
            stream=True,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        
        if response.status_code != 200:
            return False, [], None
        
        content_type = response.headers.get('content-type', '').lower()
        if 'pdf' not in content_type and not url.lower().endswith('.pdf'):
            return False, [], None
        
        pdf_bytes = response.content
        text = extract_text_from_pdf(pdf_bytes)
        
        if not text:
            return False, [], None
        
        keywords = find_sensitive_keywords(text)
        
        if keywords:
            preview_parts = []
            for kw in keywords[:5]:
                idx = text.lower().find(kw.lower())
                if idx >= 0:
                    start = max(0, idx - 30)
                    end = min(len(text), idx + len(kw) + 30)
                    context = text[start:end].replace('\n', ' ').strip()
                    preview_parts.append(f"...{context}...")
            
            preview = ' | '.join(preview_parts)[:500]
            return True, keywords, preview
        
        return True, [], None
        
    except requests.exceptions.Timeout:
        return False, [], None
    except Exception as e:
        return False, [], None


def run_pdf_analysis(scan_id, callback=None):
    """
    Run PDF deep analysis for a completed scan
    Updates findings in database with detected secrets
    
    Args:
        scan_id: Scan ID to analyze
        callback: Optional callback function(analyzed, total, secrets_found, current_url)
    """
    if PDF_LIBRARY is None:
        print("[PDF] No PDF library available (install pdfplumber or pdfminer.six)")
        return 0
    
    print(f"\n[PDF ANALYSIS] Starting for scan #{scan_id}")
    
    conn = get_db()
    
    pdf_findings = conn.execute("""
        SELECT id, url FROM findings 
        WHERE scan_id = ? 
          AND extension = '.pdf'
          AND (secrets_found IS NULL OR secrets_found = '')
          AND (status_code = 200 OR recovered = 1)
    """, (scan_id,)).fetchall()
    
    total_pdfs = len(pdf_findings)
    print(f"[PDF] Found {total_pdfs} PDFs to analyze")
    
    if total_pdfs == 0:
        conn.close()
        return 0
    
    update_scan(scan_id, step=f'PDF Analysis: 0/{total_pdfs}')
    
    analyzed = 0
    secrets_found = 0
    lock = threading.Lock()
    
    def process_pdf(finding):
        nonlocal analyzed, secrets_found
        
        finding_id = finding['id']
        url = finding['url']
        
        success, keywords, preview = analyze_pdf_url(url)
        
        with lock:
            analyzed += 1
            
            if keywords:
                secrets_found += 1
                keywords_str = ','.join(keywords[:10])
                conn.execute("""
                    UPDATE findings 
                    SET secrets_found = ?, secrets_preview = ?
                    WHERE id = ?
                """, (f"PDF_SENSITIVE:{keywords_str}", f"📄 PDF SENSITIVE: {preview}", finding_id))
                conn.commit()
                print(f"[PDF] ✓ Found secrets in: {url[:60]}...")
            
            if analyzed % 5 == 0 or analyzed == total_pdfs:
                update_scan(scan_id, step=f'PDF Analysis: {analyzed}/{total_pdfs}')
                if callback:
                    callback(analyzed, total_pdfs, secrets_found, url)
    
    # Process PDFs in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(process_pdf, f) for f in pdf_findings]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"[PDF] Worker error: {e}")
    
    # Update scan stats
    if secrets_found > 0:
        current = conn.execute("SELECT secrets_count FROM scans WHERE id = ?", (scan_id,)).fetchone()
        new_count = (current['secrets_count'] or 0) + secrets_found
        conn.execute("UPDATE scans SET secrets_count = ? WHERE id = ?", (new_count, scan_id))
        conn.commit()
    
    conn.close()
    
    print(f"[PDF] Analysis complete: {analyzed} analyzed, {secrets_found} with secrets")
    update_scan(scan_id, step=f'Completed (PDF: {secrets_found} secrets)')
    
    return secrets_found


def start_pdf_analysis_async(scan_id):
    """Start PDF analysis in background thread"""
    thread = threading.Thread(target=run_pdf_analysis, args=(scan_id,))
    thread.daemon = True
    thread.start()
    return thread
