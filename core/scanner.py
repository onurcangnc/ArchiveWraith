"""
Temporal Recon v5.9 - Wayback-Only Scan Worker
================================================
NO Live Check - Wayback Machine Only!
1. Subdomain Discovery
2. Wayback CDX API (Direct Wayback URLs - MAXIMUM COVERAGE!)
3. Filter (sensitive extensions)
4. Wayback Archive Check:
   - Snapshot exists → Download + Secret Scan
   - No snapshot → Mark for manual review
"""
import os
import re
import time
import tempfile
import shutil
import threading
from datetime import datetime
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3
urllib3.disable_warnings()

from .config import WAYBACK_WORKERS, WAYBACK_TIMEOUT
from .database import get_db, update_scan
from .filters import (is_sensitive, calc_severity, normalize_url,
                     CDX_FILTER_EXTENSIONS, path_matches_wordlist)
from .secrets import check_secrets
from .tools import (is_root_domain, run_subdomain_discovery,
                   run_wayback_cdx, filter_urls)

# Wayback check workers
WAYBACK_RATE_LIMIT = 1  # seconds between requests


def clean_null(s):
    """Remove NULL characters from string"""
    if s is None:
        return ''
    return str(s).replace('\x00', '').strip()


def run_recon_pipeline(domain, callback=None):
    """Full recon pipeline for root domains - WAYBACK ONLY!

    Pipeline:
    1. Subdomain Discovery (subfinder + assetfinder)
    2. Wayback CDX API → ALL subdomains (Wayback Machine URLs - MAXIMUM COVERAGE!)
    3. Filtering → ALL URLs (sensitive extensions)
    """
    print(f"\n{'='*60}\n[RECON PIPELINE - WAYBACK ONLY] {domain}\n{'='*60}")

    output_dir = tempfile.mkdtemp(prefix=f'temporal_{domain}_')

    try:
        # 1/3: Subdomain Discovery
        subs_file, subs_count = run_subdomain_discovery(domain, output_dir, callback)
        if not subs_file or subs_count == 0:
            subs_file = os.path.join(output_dir, 'subdomains.txt')
            with open(subs_file, 'w') as f:
                f.write(domain)
            subs_count = 1
        else:
            # Add ROOT domain to Wayback input
            with open(subs_file, 'a') as f:
                f.write(f'\n{domain}')
            subs_count += 1

        # 2/3: Wayback CDX API → ALL subdomains (MAXIMUM COVERAGE!)
        if callback:
            callback('[2/3] Wayback CDX: Fetching URLs from Wayback...')

        urls_file, urls_count = run_wayback_cdx(
            subs_file, output_dir, callback=callback
        )

        if urls_count == 0:
            return [], subs_count, "No URLs found from Wayback Machine"

        # 3/3: Filtering
        if callback:
            callback(f'[3/3] Filtering {urls_count:,} URLs...')

        with open(urls_file) as f:
            all_urls = [clean_null(l) for l in f if clean_null(l)]

        filtered = filter_urls(all_urls, callback)

        print(f"[✓] Filtered: {len(all_urls):,} → {len(filtered):,} sensitive URLs")
        if callback:
            callback(f'[3/3] Filtered: {len(filtered):,} sensitive URLs')

        shutil.rmtree(output_dir, ignore_errors=True)
        return filtered, subs_count, None

    except Exception as e:
        import traceback
        traceback.print_exc()
        return [], 0, str(e)


def fetch_cdx(domain, callback=None, timeout=300):
    """Main URL fetching function"""
    is_root = is_root_domain(domain)

    print(f"\n[*] Target: {domain}")
    print(f"[*] Type: {'Root domain' if is_root else 'Subdomain'}")

    if not is_root:
        # Single subdomain - use Wayback CDX API directly
        print(f"\n[Wayback CDX] Fetching URLs for {domain}...")
        if callback:
            callback(f'[1/2] Wayback CDX: Fetching URLs...')

        try:
            from tools import fetch_cdx_domain
            urls = fetch_cdx_domain(domain, timeout=timeout)

            print(f"[✓] Wayback CDX: {len(urls):,} URLs")
            if callback:
                callback(f'[1/2] Wayback CDX: {len(urls):,} URLs')
        except Exception as e:
            return [], str(e)

        if callback:
            callback(f'[2/2] Filtering {len(urls):,} URLs...')

        filtered = filter_urls(list(urls), callback)
        print(f"[✓] Filtered: {len(urls):,} → {len(filtered):,} sensitive URLs")
        if callback:
            callback(f'[2/2] ✓ {len(filtered):,} sensitive URLs')
        return filtered, 1, None  # Single subdomain

    return run_recon_pipeline(domain, callback)


def check_wayback_url(url):
    """Check if URL exists in Wayback Machine and download content

    Returns:
        dict with keys:
        - url: original URL
        - wayback_url: snapshot URL or None
        - content: downloaded content or None
        - secrets: list of secret types found
        - has_snapshot: bool
    """
    result = {
        'url': url,
        'wayback_url': None,
        'content': None,
        'secrets': [],
        'has_snapshot': False
    }

    try:
        # Check Wayback API
        api_url = f"https://archive.org/wayback/available?url={quote(url, '')}"
        response = requests.get(api_url, timeout=WAYBACK_TIMEOUT)

        if response.ok:
            data = response.json()
            snapshot = data.get('archived_snapshots', {}).get('closest')

            if snapshot and snapshot.get('available'):
                result['has_snapshot'] = True
                result['wayback_url'] = snapshot.get('url', '')

                # Download content
                try:
                    content_response = requests.get(
                        result['wayback_url'],
                        timeout=15,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                    )
                    if content_response.ok:
                        result['content'] = content_response.text[:50000]
                        result['secrets'] = check_secrets(result['content'])
                except:
                    pass  # Content download failed, but we have snapshot URL

    except Exception:
        pass  # Wayback check failed

    return result


def run_scan(scan_id, domain):
    """Main scan worker - WAYBACK ONLY (No Live Check)"""
    print(f"\n{'='*60}\n[SCAN #{scan_id}] {domain}\n{'='*60}")
    update_scan(scan_id, status='running', started_at=datetime.now(), step='Initializing...')

    try:
        def progress_callback(msg):
            update_scan(scan_id, step=msg)

        urls, total_discovered_subdomains, error = fetch_cdx(domain, progress_callback, timeout=300)

        if error:
            update_scan(scan_id, status='error', step='Error', error_message=error)
            return

        if not urls:
            update_scan(scan_id, status='completed', step='No sensitive URLs found',
                       completed_at=datetime.now(), total_urls=0,
                       unique_subdomains=total_discovered_subdomains)
            return

        # Deduplicate
        unique = {}
        for u in urls:
            u = clean_null(u)
            if not u:
                continue
            n = normalize_url(u)
            if n not in unique:
                unique[n] = u
        urls = list(unique.values())

        subdomains = set()
        for u in urls:
            try:
                subdomains.add(urlparse(u).netloc.lower())
            except:
                pass

        total = len(urls)
        print(f"[*] {total:,} sensitive URLs from {len(subdomains)} subdomains (discovered: {total_discovered_subdomains:,})")

        update_scan(scan_id, total_urls=total, sensitive_urls=total,
                   unique_subdomains=total_discovered_subdomains, step='Checking Wayback...')

        # Wayback check (NO live requests to target!)
        checked = 0
        findings = []
        start_time = time.time()
        lock = threading.Lock()

        def check_url(url):
            nonlocal checked

            url = clean_null(url)
            if not url:
                with lock:
                    checked += 1
                return None

            try:
                subdomain = urlparse(url).netloc.lower()
            except:
                subdomain = domain

            sens, ext = is_sensitive(url)
            if not sens:
                with lock:
                    checked += 1
                return None

            # Check Wayback
            wb_result = check_wayback_url(url)

            result = {
                'url': url,
                'subdomain': subdomain,
                'extension': ext or '',
                'status': None,  # No live status (we don't check live!)
                'secrets': wb_result['secrets'],
                'recovered': wb_result['has_snapshot'],
                'preview': '',
                'wayback_url': wb_result['wayback_url'] or ''
            }

            # Build preview
            if wb_result['has_snapshot']:
                if wb_result['content']:
                    if wb_result['secrets']:
                        secret_names = ', '.join(wb_result['secrets'])
                        result['preview'] = f"📦 Wayback Snapshot Found\n🔑 Secrets: {secret_names}\n\n{wb_result['content'][:400]}"
                    else:
                        result['preview'] = f"📦 Wayback Snapshot Found\n🔗 {wb_result['wayback_url']}\n\n{wb_result['content'][:400]}"
                else:
                    result['preview'] = f"📦 Wayback Snapshot Exists\n🔗 {wb_result['wayback_url']}\n(Content download failed)"
            else:
                result['preview'] = "🔍 No Wayback Snapshot - Manual Check Required"

            # Progress update
            with lock:
                checked += 1
                if checked % 50 == 0:
                    elapsed = time.time() - start_time
                    rate = int(checked / elapsed) if elapsed > 0 else 0
                    update_scan(scan_id, checked_urls=checked, urls_per_sec=rate,
                               step=f'Wayback: {checked:,}/{total:,}')

            # Return ALL URLs (never filter out)
            return result

        # Process URLs with thread pool
        with ThreadPoolExecutor(max_workers=WAYBACK_WORKERS) as executor:
            futures = {executor.submit(check_url, u): u for u in urls}
            for future in as_completed(futures):
                try:
                    r = future.result()
                    if r:
                        findings.append(r)
                except:
                    pass

        # Save findings
        update_scan(scan_id, step='Saving findings...')

        conn = get_db()
        crit = high = med = rec = sec = 0

        for f in findings:
            url = clean_null(f['url'])
            subdomain = clean_null(f['subdomain'])
            extension = clean_null(f['extension'])
            preview = clean_null(f['preview'])[:1000]

            if not url:
                continue

            sev, score = calc_severity(url, extension, f['secrets'])
            secrets_str = ','.join(f['secrets']) if f['secrets'] else ''

            if sev == 'critical':
                crit += 1
            elif sev == 'high':
                high += 1
            else:
                med += 1
            if f['recovered']:
                rec += 1
            if f['secrets']:
                sec += 1

            try:
                conn.execute("""INSERT INTO findings
                    (scan_id, subdomain, url, url_normalized, severity, extension, score,
                     status_code, secrets_found, secrets_preview, recovered)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (scan_id, subdomain, url, normalize_url(url), sev,
                     extension, score, f['status'], secrets_str, preview,
                     1 if f['recovered'] else 0))
            except Exception as e:
                print(f"[!] Error inserting finding: {e}")
                continue

        conn.commit()
        conn.close()

        # Calculate duration
        duration = int(time.time() - start_time)

        update_scan(scan_id, status='completed', step='Completed',
                   completed_at=datetime.now(), duration=duration,
                   total_findings=len(findings),
                   critical_count=crit, high_count=high, medium_count=med,
                   recovered_count=rec, secrets_count=sec,
                   checked_urls=checked, live_urls=rec)

        print(f"\n[DONE] Scan #{scan_id}: {len(findings)} findings (C:{crit} H:{high} M:{med})")
        print(f"      Wayback snapshots: {rec}, Secrets found: {sec}")

    except Exception as e:
        import traceback
        traceback.print_exc()
        update_scan(scan_id, status='error', error_message=str(e), step='Error')
