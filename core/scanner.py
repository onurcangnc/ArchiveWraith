"""
ArchiveWraith - Hybrid Scan Worker
==================================
Golden Method + Live Check:
1. Subdomain Discovery (subfinder + assetfinder)
2. Wayback URLs (waybackurls)
3. Filter (sensitive extensions)
4. Hybrid Check:
   - 404/400/403/410 → GOLDEN METHOD (Wayback for deleted files)
   - 200/301/302 → Live content + Secret scan
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

        # 2/3: Wayback CDX API → ALL subdomains via WILDCARD (MAXIMUM COVERAGE!)
        if callback:
            callback('[2/3] Wayback CDX: Fetching URLs from Wayback...')

        urls_file, urls_count, wayback_subs = run_wayback_cdx(
            subs_file, output_dir, callback=callback
        )

        # Use the higher subdomain count (discovered vs wayback)
        # Wayback might find more subdomains than subfinder/assetfinder
        if wayback_subs > subs_count:
            print(f"[+] Wayback found more subdomains: {wayback_subs:,} vs discovered {subs_count:,}")
            subs_count = wayback_subs

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
            from .tools import fetch_cdx_domain
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

        # Step 1: Domain-based live check (1 request per domain instead of per URL)
        domain_status = {}  # Cache domain status: {domain: status_code}

        def check_domain_status(subdomain):
            """Check if domain is live (cached)"""
            if subdomain in domain_status:
                return domain_status[subdomain]

            try:
                resp = requests.head(f"https://{subdomain}/", timeout=5,
                                    allow_redirects=True,
                                    headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
                domain_status[subdomain] = resp.status_code
            except:
                domain_status[subdomain] = None  # Unreachable

            return domain_status[subdomain]

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

            # Get domain status (cached)
            domain_live_status = check_domain_status(subdomain)

            result = {
                'url': url,
                'subdomain': subdomain,
                'extension': ext or '',
                'status': domain_live_status,
                'secrets': [],
                'recovered': False,
                'preview': '',
                'wayback_url': ''
            }

            # ALWAYS check Wayback first
            wb_result = check_wayback_url(url)
            result['wayback_url'] = wb_result['wayback_url'] or ''

            # Domain DEAD (404/400/403/None) → Only Wayback (Golden Method)
            if domain_live_status is None or domain_live_status >= 400:
                result['secrets'] = wb_result['secrets']
                result['recovered'] = wb_result['has_snapshot']

                if wb_result['has_snapshot']:
                    if wb_result['content']:
                        if wb_result['secrets']:
                            secret_names = ', '.join(wb_result['secrets'])
                            result['preview'] = f"🏆 GOLDEN METHOD: Deleted file recovered!\n📦 Domain Status: {domain_live_status or 'Unreachable'}\n🔑 Secrets: {secret_names}\n\n{wb_result['content'][:400]}"
                        else:
                            result['preview'] = f"🏆 GOLDEN METHOD: Deleted file recovered!\n📦 Domain Status: {domain_live_status or 'Unreachable'}\n🔗 {wb_result['wayback_url']}\n\n{wb_result['content'][:400]}"
                    else:
                        result['preview'] = f"🏆 GOLDEN METHOD: Deleted file found!\n📦 Domain Status: {domain_live_status or 'Unreachable'}\n🔗 {wb_result['wayback_url']}"
                else:
                    result['preview'] = f"❌ Domain: {domain_live_status or 'Unreachable'} - No Wayback snapshot"

            # Domain LIVE (200-399) → Check live content + Wayback
            else:
                try:
                    live_content = requests.get(url, timeout=10,
                                               headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
                    if live_content.ok:
                        content = live_content.text[:50000]
                        live_secrets = check_secrets(content)

                        # Combine secrets from both live and wayback
                        all_secrets = list(set(live_secrets + wb_result['secrets']))
                        result['secrets'] = all_secrets
                        result['recovered'] = wb_result['has_snapshot']

                        if all_secrets:
                            secret_names = ', '.join(all_secrets)
                            wayback_note = f"\n📦 Wayback: {wb_result['wayback_url']}" if wb_result['has_snapshot'] else ""
                            result['preview'] = f"🟢 LIVE: Status {live_content.status_code}\n🔑 Secrets: {secret_names}{wayback_note}\n\n{content[:400]}"
                        else:
                            wayback_note = f"\n📦 Wayback: Available" if wb_result['has_snapshot'] else ""
                            result['preview'] = f"🟢 LIVE: Status {live_content.status_code}{wayback_note}\n\n{content[:300]}"
                    else:
                        # Live returned error, use wayback
                        result['secrets'] = wb_result['secrets']
                        result['recovered'] = wb_result['has_snapshot']
                        if wb_result['has_snapshot']:
                            result['preview'] = f"⚠️ Live: {live_content.status_code}\n📦 Wayback: {wb_result['wayback_url']}"
                        else:
                            result['preview'] = f"⚠️ Live: {live_content.status_code} - No Wayback"
                except:
                    # Live fetch failed, use wayback
                    result['secrets'] = wb_result['secrets']
                    result['recovered'] = wb_result['has_snapshot']
                    if wb_result['has_snapshot']:
                        result['preview'] = f"⚠️ Live fetch failed\n📦 Wayback: {wb_result['wayback_url']}"
                    else:
                        result['preview'] = f"⚠️ Live fetch failed - No Wayback"

            # Progress update
            with lock:
                checked += 1
                if checked % 50 == 0:
                    elapsed = time.time() - start_time
                    rate = int(checked / elapsed) if elapsed > 0 else 0
                    update_scan(scan_id, checked_urls=checked, urls_per_sec=rate,
                               step=f'Checking: {checked:,}/{total:,}')

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
