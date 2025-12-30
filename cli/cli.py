#!/usr/bin/env python3
"""
ArchiveWraith CLI
100% Stealth Wayback Machine Reconnaissance Tool
Like a wraith in the archives - invisible, silent, deadly.
"""
import argparse
import sys
import os
import tempfile
import shutil
from urllib.parse import urlparse

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import fetch_cdx, run_recon_pipeline
from core.tools import filter_urls, is_root_domain, run_subdomain_discovery, fetch_cdx_domain


def print_banner():
    """Print tool banner"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║         ArchiveWraith - Stealth Wayback Recon                ║
║     100% Passive - Zero Requests to Target Servers          ║
║        Like a wraith in the archives...                      ║
╚══════════════════════════════════════════════════════════════╝
    """)


def print_stats(results):
    """Print scan results statistics"""
    if not results:
        print("\n[✗] No results found")
        return

    # Count by severity
    severity_counts = {}
    subdomains = set()

    for r in results:
        sev = r.get('severity', 'medium')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        try:
            subdomains.add(urlparse(r['url']).netloc.lower())
        except:
            pass

    total = len(results)
    critical = severity_counts.get('critical', 0)
    high = severity_counts.get('high', 0)
    medium = severity_counts.get('medium', 0)

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                        RESULTS SUMMARY                         ║
╠══════════════════════════════════════════════════════════════╣
║  Total URLs:         {total:>10,}                              ║
║  Unique Subdomains:  {len(subdomains):>10,}                              ║
╠══════════════════════════════════════════════════════════════╣
║  Critical:           {critical:>10,}                              ║
║  High:               {high:>10,}                              ║
║  Medium:             {medium:>10,}                              ║
╚══════════════════════════════════════════════════════════════╝
    """)


def print_results(results, limit=50):
    """Print top findings"""
    if not results:
        return

    # Sort by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2}
    sorted_results = sorted(results, key=lambda x: severity_order.get(x.get('severity', 'medium'), 3))

    print(f"\n[*] Top {min(limit, len(sorted_results))} Findings:")
    print("─" * 80)

    for i, r in enumerate(sorted_results[:limit], 1):
        sev = r.get('severity', 'medium')
        sev_icon = {'critical': '💀', 'high': '🔴', 'medium': '🟠'}.get(sev, '⚪')
        url = r.get('url', 'N/A')[:70]

        print(f"{i:3}. [{sev_icon}] {url}")

        if r.get('has_snapshot'):
            print(f"     └─ Wayback: {r.get('wayback_url', 'N/A')[:60]}...")

        if r.get('secrets'):
            secrets = ', '.join(r['secrets'])
            print(f"     └─ Secrets: {secrets}")


def save_results(results, output_file):
    """Save results to file"""
    with open(output_file, 'w') as f:
        f.write("# HistoryFinder Results\n")
        f.write("# URL | Severity | Wayback URL | Secrets\n\n")

        for r in results:
            sev = r.get('severity', 'medium')
            url = r.get('url', 'N/A')
            wb = r.get('wayback_url', 'N/A')
            secrets = ','.join(r.get('secrets', []))

            f.write(f"{url} | {sev} | {wb} | {secrets}\n")

    print(f"\n[✓] Results saved to: {output_file}")


def cmd_scan(args):
    """Run scan on domain"""
    print_banner()

    domain = args.domain
    is_root = is_root_domain(domain)

    print(f"[*] Target: {domain}")
    print(f"[*] Type: {'Root Domain' if is_root else 'Subdomain'}")
    print(f"[*] Output: {args.output}")

    # Progress callback
    def progress(msg):
        print(f"    {msg}")

    print(f"\n[1/2] Fetching URLs from Wayback CDX API...")
    urls, total_discovered_subdomains, error = fetch_cdx(domain, progress, timeout=args.timeout)

    if error:
        print(f"\n[✗] Error: {error}")
        return 1

    if not urls:
        print("\n[✗] No URLs found")
        return 0

    print(f"\n[2/2] Filtering {len(urls):,} URLs...")
    filtered = filter_urls(urls, progress)

    print(f"\n[✓] Found {len(filtered):,} sensitive URLs from {total_discovered_subdomains:,} discovered subdomains")

    # Save results
    if args.output:
        results = [{'url': u, 'severity': 'medium'} for u in filtered]
        save_results(results, args.output)
    else:
        # Print as results dict
        results = [{'url': u, 'severity': 'medium'} for u in filtered]
        print_stats(results)
        print_results(results, limit=args.limit)

    return 0


def cmd_subdomains(args):
    """Discover subdomains only"""
    print_banner()

    from core.tools import run_subdomain_discovery

    domain = args.domain
    print(f"[*] Target: {domain}")

    output_dir = tempfile.mkdtemp(prefix=f'temporal_{domain}_')

    try:
        subs_file, subs_count = run_subdomain_discovery(domain, output_dir)

        print(f"\n[✓] Found {subs_count:,} subdomains")

        if args.output:
            shutil.copy(subs_file, args.output)
            print(f"[✓] Saved to: {args.output}")
        else:
            with open(subs_file) as f:
                for line in f:
                    print(line.strip())

    finally:
        shutil.rmtree(output_dir, ignore_errors=True)

    return 0


def cmd_urls(args):
    """Fetch URLs from Wayback for domain"""
    print_banner()

    from tools import fetch_cdx_domain

    domain = args.domain
    print(f"[*] Target: {domain}")
    print(f"[*] Fetching URLs from Wayback CDX API...")

    urls = fetch_cdx_domain(domain, timeout=args.timeout)

    print(f"\n[✓] Found {len(urls):,} URLs")

    if args.output:
        with open(args.output, 'w') as f:
            for url in sorted(urls):
                f.write(url + '\n')
        print(f"[✓] Saved to: {args.output}")
    else:
        if args.limit:
            for i, url in enumerate(sorted(urls)[:args.limit], 1):
                print(f"{i:5}. {url[:100]}")
        else:
            for url in sorted(urls):
                print(url)

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog='archivewraith',
        description='ArchiveWraith - 100% Stealth Wayback Recon',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan example.com                    # Scan root domain
  %(prog)s scan sub.example.com                # Scan subdomain
  %(prog)s scan example.com -o results.txt    # Save to file
  %(prog)s scan example.com -l 100             # Show top 100 results
  %(prog)s subdomains example.com              # Subdomain discovery only
  %(prog)s urls sub.example.com                # Fetch Wayback URLs only

Rate Limiting:
  - CDX API: ~1 request/second (compliant with Wayback limits)
  - Large scans: 14K domains ~4 hours
  - Exponential backoff on 429/503 errors

For more info: https://github.com/yourusername/ArchiveWraith
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run full recon scan')
    scan_parser.add_argument('domain', help='Domain to scan')
    scan_parser.add_argument('-o', '--output', help='Output file')
    scan_parser.add_argument('-l', '--limit', type=int, default=50, help='Limit results (default: 50)')
    scan_parser.add_argument('-t', '--timeout', type=int, default=300, help='Timeout in seconds (default: 300)')

    # Subdomains command
    sub_parser = subparsers.add_parser('subdomains', help='Discover subdomains')
    sub_parser.add_argument('domain', help='Domain to enumerate')
    sub_parser.add_argument('-o', '--output', help='Output file')

    # URLs command
    urls_parser = subparsers.add_parser('urls', help='Fetch Wayback URLs')
    urls_parser.add_argument('domain', help='Domain to query')
    urls_parser.add_argument('-o', '--output', help='Output file')
    urls_parser.add_argument('-l', '--limit', type=int, help='Limit results')
    urls_parser.add_argument('-t', '--timeout', type=int, default=60, help='Timeout in seconds')

    # Version
    parser.add_argument('-v', '--version', action='version', version='ArchiveWraith v1.0')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Route to command
    if args.command == 'scan':
        return cmd_scan(args)
    elif args.command == 'subdomains':
        return cmd_subdomains(args)
    elif args.command == 'urls':
        return cmd_urls(args)

    return 0


if __name__ == '__main__':
    sys.exit(main())
