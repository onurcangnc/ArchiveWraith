"""
Temporal Recon v5.9 - External Tools
====================================
Wayback-Only Mode:
- subfinder + assetfinder (subdomain discovery)
- Wayback CDX API (Direct Wayback URLs - MORE coverage!)
- uro (URL deduplication)

NO httpx, NO puredns, NO live check
"""
import os
import subprocess
import shutil
import time
import re
import requests
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

from .filters import CDX_FILTER_EXTENSIONS, path_matches_wordlist


def is_root_domain(domain):
    """Check if domain is root or subdomain"""
    sld_tlds = {'co.uk', 'org.uk', 'ac.uk', 'com.tr', 'org.tr', 'edu.tr',
                'com.br', 'org.br', 'com.au', 'co.jp', 'or.jp', 'ac.jp'}
    parts = domain.lower().replace('www.', '').split('.')
    if len(parts) >= 3:
        last_two = f"{parts[-2]}.{parts[-1]}"
        if last_two in sld_tlds:
            return len(parts) == 3
    return len(parts) == 2


def find_tool(name, extra_paths=None):
    """Find tool binary - Linux/Unix paths only"""
    path = shutil.which(name)
    if path:
        return path

    for p in (extra_paths or []):
        if os.path.exists(p):
            return p

    go_bins = [
        os.path.expanduser('~/go/bin/' + name),
        '/root/go/bin/' + name,
        '/usr/local/bin/' + name,
    ]
    for p in go_bins:
        if os.path.exists(p):
            return p

    return None


def run_subfinder(domain):
    """Run subfinder, return set of subdomains"""
    tool = find_tool('subfinder', ['/root/go/bin/subfinder', '/usr/local/bin/subfinder'])
    if not tool:
        print("  [!] subfinder not installed")
        return set()

    try:
        result = subprocess.run(
            [tool, '-d', domain, '-silent', '-all'],
            capture_output=True, text=True
        )
        subs = set(line.strip().lower() for line in result.stdout.strip().split('\n') if line.strip())
        print(f"  [+] subfinder: {len(subs):,}")
        return subs
    except Exception as e:
        print(f"  [!] subfinder error: {e}")
        return set()


def run_assetfinder(domain):
    """Run assetfinder, return set of subdomains"""
    tool = find_tool('assetfinder', ['/root/go/bin/assetfinder', '/usr/local/bin/assetfinder'])
    if not tool:
        print("  [!] assetfinder not installed")
        return set()

    try:
        result = subprocess.run(
            [tool, '--subs-only', domain],
            capture_output=True, text=True
        )
        subs = set()
        for line in result.stdout.strip().split('\n'):
            sub = line.strip().lower()
            if sub and sub.endswith(domain):
                subs.add(sub)
        print(f"  [+] assetfinder: {len(subs):,}")
        return subs
    except Exception as e:
        print(f"  [!] assetfinder error: {e}")
        return set()


def run_subdomain_discovery(domain, output_dir, callback=None):
    """
    Combined subdomain discovery: subfinder + assetfinder
    Returns deduplicated results from both tools
    """
    output = os.path.join(output_dir, 'subdomains.txt')

    print(f"\n[SUBDOMAIN DISCOVERY] {domain}")
    print("=" * 50)
    if callback:
        callback(f'[1/3] Subdomain discovery: Running 2 tools...')

    all_subs = set()

    if callback:
        callback(f'[1/3] Running subfinder...')
    subfinder_subs = run_subfinder(domain)
    all_subs.update(subfinder_subs)

    if callback:
        callback(f'[1/3] Running assetfinder... ({len(all_subs):,} so far)')
    assetfinder_subs = run_assetfinder(domain)
    all_subs.update(assetfinder_subs)

    all_subs.add(domain)

    print("=" * 50)
    print(f"[✓] TOTAL: {len(all_subs):,} unique subdomains")
    print(f"    subfinder: {len(subfinder_subs):,}")
    print(f"    assetfinder: {len(assetfinder_subs):,}")

    only_subfinder = subfinder_subs - assetfinder_subs
    only_assetfinder = assetfinder_subs - subfinder_subs
    print(f"    [unique] subfinder: +{len(only_subfinder):,}")
    print(f"    [unique] assetfinder: +{len(only_assetfinder):,}")

    if callback:
        callback(f'[1/3] ✓ {len(all_subs):,} subdomains (2 tools merged)')

    with open(output, 'w') as f:
        f.write('\n'.join(sorted(all_subs)))

    return output, len(all_subs)


# ============================================================================
# WAYBACK CDX API - Direct Wayback URL fetching
# ============================================================================

def fetch_cdx_domain(domain, timeout=30, delay=1.0, max_retries=3):
    """
    Fetch Wayback URLs for a single subdomain using CDX API.

    Args:
        domain: Subdomain to query
        timeout: Request timeout
        delay: Delay after request (rate limiting)
        max_retries: Max retries on 429/503 errors

    Returns: set of URLs
    """
    urls = set()

    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url={domain}/*"
        f"&collapse=urlkey"
        f"&output=text"
        f"&fl=original"
        f"&limit=500000"
    )

    for attempt in range(max_retries):
        try:
            response = requests.get(cdx_url, timeout=timeout)

            if response.status_code == 200:
                for line in response.text.strip().split('\n'):
                    line = line.strip()
                    if line:
                        urls.add(line)
                break  # Success, exit retry loop

            elif response.status_code == 429:
                wait_time = (attempt + 1) * 5  # 5, 10, 15 seconds
                print(f"  [!] {domain}: Rate limited (429) - waiting {wait_time}s")
                time.sleep(wait_time)
                if attempt < max_retries - 1:
                    continue  # Retry
                else:
                    print(f"  [!] {domain}: Max retries reached for 429")
                    break

            elif response.status_code == 503:
                wait_time = (attempt + 1) * 3  # 3, 6, 9 seconds
                print(f"  [!] {domain}: Service unavailable (503) - waiting {wait_time}s")
                time.sleep(wait_time)
                if attempt < max_retries - 1:
                    continue
                else:
                    break

            else:
                # Other status codes, don't retry
                break

        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                time.sleep(2)
                continue
            break
        except Exception as e:
            break

    # Rate limiting delay (always apply after last attempt)
    if delay > 0:
        time.sleep(delay)

    return urls


def fetch_cdx_parallel(domains, max_workers=20, callback=None):
    """
    Fetch Wayback URLs for multiple domains in parallel using CDX API.
    Falls back to domain-by-domain if wildcard fails.

    Returns: set of URLs
    """
    import threading

    if not domains:
        return set()

    root_domain = domains[0].split('.')[-2:] if len(domains[0].split('.')) >= 2 else domains[0]
    root_domain = '.'.join(root_domain)

    # NOTE: Wildcard only returns main domains, NOT all subdomains!
    # Skip wildcard, go directly to domain-by-domain for MAXIMUM coverage
    print(f"\n[CDX] Domain-by-domain parallel ({len(domains):,} domains, {max_workers} workers)")
    print(f"[!] Skipping wildcard - it only covers main domains, not all subdomains")

    urls = set()
    processed = 0
    start = time.time()
    lock = threading.Lock()

    def process_single(subdomain):
        nonlocal processed
        sub_urls = fetch_cdx_domain(subdomain, timeout=15, delay=2.0)

        with lock:
            processed += 1
            if processed % 100 == 0:
                elapsed = time.time() - start
                rate = processed / elapsed if elapsed > 0 else 0
                eta = (len(domains) - processed) / rate if rate > 0 else 0
                eta_str = f"{int(eta//60)}m" if eta > 60 else f"{int(eta)}s"
                print(f"  [CDX] {processed:,}/{len(domains):,} | {len(urls):,} URLs | ETA: {eta_str}")
                if callback:
                    callback(f'[2/3] cdx: {processed:,}/{len(domains):,} | {len(urls):,} URLs | ETA: {eta_str}')

        return sub_urls

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single, d): d for d in domains}

        for future in as_completed(futures):
            try:
                domain_urls = future.result()
                urls.update(domain_urls)

                if len(domain_urls) > 0:
                    print(f"  [+] {futures[future]}: {len(domain_urls):,} URLs")
            except:
                pass

    print(f"[✓] CDX parallel: {len(urls):,} URLs from {len(domains):,} domains")
    return list(urls)


def run_wayback_cdx(input_file, output_dir, callback=None):
    """
    Fetch Wayback URLs using CDX API instead of GAU.

    Hybrid strategy:
    1. Try wildcard request first (single request, fast)
    2. If low results, fall back to parallel domain-by-domain

    This gives MAXIMUM Wayback coverage!
    """
    if not input_file or not os.path.exists(input_file):
        print("[!] No input file for Wayback CDX")
        return None, 0

    with open(input_file) as f:
        domains = [l.strip() for l in f if l.strip()]

    total = len(domains)
    if total == 0:
        print("[!] No domains to process")
        return None, 0

    # Adaptive workers based on domain count
    # NOTE: CDX API has 1 req/sec rate limit!
    # For large scans, use fewer workers to avoid 429 errors
    if total > 10000:
        max_workers = 2  # Very conservative for large scans (14K domains)
    elif total > 5000:
        max_workers = 3
    elif total > 1000:
        max_workers = 3
    else:
        max_workers = 3  # Small scans can be slightly faster

    print(f"\n[WAYBACK CDX] Processing {total:,} domains (workers: {max_workers})...")
    if callback:
        callback(f'[2/3] Wayback CDX: Fetching URLs...')

    urls = fetch_cdx_parallel(domains, max_workers=max_workers, callback=callback)

    if not urls:
        print("[!] No URLs found from Wayback CDX")
        return None, 0

    # Save to file
    output = os.path.join(output_dir, 'urls.txt')
    with open(output, 'w') as f:
        f.write('\n'.join(sorted(urls)))

    print(f"[✓] Wayback CDX: {len(urls):,} URLs")
    if callback:
        callback(f'[2/3] ✓ Wayback CDX: {len(urls):,} URLs')

    return output, len(urls)


# ============================================================================
# URL Filtering
# ============================================================================

def filter_urls(urls, callback=None):
    """Filter URLs by extension and wordlist"""
    ext_pattern = re.compile(rf'\.({CDX_FILTER_EXTENSIONS})(\?|#|$)', re.I)
    filtered = []

    for url in urls:
        if ext_pattern.search(url):
            filtered.append(url)
        else:
            matches, _ = path_matches_wordlist(url)
            if matches:
                filtered.append(url)

    return filtered
