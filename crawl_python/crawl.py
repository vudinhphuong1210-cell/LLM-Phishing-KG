#!/usr/bin/env python3
"""
Crawl phishing/scam URLs tu cac nguon:
  - tinnhiemmang.vn  -> website-lua-dao (scam), website-tin-nhiem (legit)
  - chongluadao.vn   -> database/denylist (scam), database/allowlist (legit)

Output: cap nhat vao data/eval_black_list.txt va eval_white_list.txt
"""

import requests
import re
import os
import sys
import argparse
import time
import socket
from urllib.parse import urlparse

# Fix console encoding for Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore

# ============================================================
# Config paths
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
DATA_DIR = os.path.join(PROJECT_DIR, "data")
BLACK_FILE = os.path.join(DATA_DIR, "eval_black_list.txt")
WHITE_FILE = os.path.join(DATA_DIR, "eval_white_list.txt")

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )
}
TIMEOUT = 30
DELAY = 0.5  # seconds between requests
DNS_TIMEOUT = 3  # seconds for DNS check


# ============================================================
# Helpers
# ============================================================
def domain_only(url_or_domain: str) -> str:
    """Normalize to plain domain (lowercase, strip protocol/www)."""
    s = url_or_domain.strip().lower()
    if s.startswith("http://"):
        s = s[7:]
    elif s.startswith("https://"):
        s = s[8:]
    if s.startswith("www."):
        s = s[4:]
    if "/" in s:
        s = s.split("/")[0]
    return s.strip()


def read_domains(path: str) -> set:
    """Read domain list from file (one per line)."""
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


def write_domains(path: str, domains: set):
    """Write domain list to file, sorted A->Z."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for d in sorted(domains, key=lambda x: x.lower()):
            f.write(d + "\n")


def resolve_domain(domain: str, timeout: int = DNS_TIMEOUT) -> bool:
    """
    Quick DNS check — returns True if domain resolves.
    Uses low timeout (3s) to avoid hanging on dead domains.
    """
    if not domain:
        return False
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            socket.gethostbyname(domain)
            return True
        except (socket.gaierror, OSError):
            return False
        finally:
            socket.setdefaulttimeout(old_timeout)
    except Exception:
        return False


def safe_get(url: str, check_dns: bool = True, **kwargs) -> requests.Response | None:
    """GET request with DNS pre-check and retry.

    Returns Response on success, None if DNS fails or all retries exhausted.
    """
    # DNS pre-check nếu được yêu cầu
    if check_dns:
        domain = domain_only(url)
        if not resolve_domain(domain):
            return None

    for attempt in range(3):
        try:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, **kwargs)
            resp.raise_for_status()
            return resp
        except requests.ConnectionError as e:
            # Connection error often = DNS or network issue
            if attempt == 2:
                return None
            time.sleep(2 ** attempt * 0.5)
        except requests.Timeout:
            if attempt == 2:
                return None
            time.sleep(2 ** attempt * 0.5)
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else 0
            if code in (404, 410):
                return None
            if attempt == 2 or code >= 500:
                return None
            time.sleep(2 ** attempt * 0.5)
        except requests.RequestException:
            if attempt == 2:
                return None
            time.sleep(2 ** attempt * 0.5)

    return None


# ============================================================
# Crawler: tinnhiemmang.vn
# ============================================================
def crawl_tinnhiem_blacklist(max_pages: int = None) -> set:
    """
    Scam list from /website-lua-dao
    ~20 items/page, ~6281 pages total.
    """
    print("[tinnhiemmang] Crawl scam website list (denylist)...")
    base = "https://tinnhiemmang.vn/website-lua-dao"
    domains = set()

    resp = safe_get(base)
    if resp is None:
        print("  ERROR: Cannot reach tinnhiemmang.vn")
        return domains

    pages = re.findall(r"page=(\d+)", resp.text)
    total_pages = max(int(p) for p in pages) if pages else 1
    if max_pages:
        total_pages = min(total_pages, max_pages)
    print(f"  Total pages: {total_pages}")

    domains |= _parse_tinnhiem_black_items(resp.text)

    for page in range(2, total_pages + 1):
        url = f"{base}?page={page}"
        resp = safe_get(url)
        if resp is None:
            print(f"  [skip] page {page}: unreachable")
            # Short delay even on skip to not hammer the server
            time.sleep(DELAY)
            continue
        page_domains = _parse_tinnhiem_black_items(resp.text)
        if not page_domains:
            print(f"  Page {page} has no data, stopping.")
            break
        domains |= page_domains
        if page % 50 == 0 or page == total_pages:
            print(f"  Crawled {page}/{total_pages} pages - {len(domains)} domains")
        time.sleep(DELAY)

    print(f"  => Total: {len(domains)} scam domains from tinnhiemmang.vn")
    return domains


def _parse_tinnhiem_black_items(html: str) -> set:
    """
    Parse domain items from tinnhiemmang.vn scam list (website-lua-dao).
    Structure: <span class="...webkit-box-2...">domain.com</span>
    """
    domains = set()
    for m in re.finditer(
        r'<span[^>]*class="[^"]*webkit-box-2[^"]*"[^>]*>\s*(.*?)\s*</span>',
        html, re.DOTALL
    ):
        raw = m.group(1).strip()
        d = domain_only(raw)
        if d:
            domains.add(d)
    return domains


def crawl_tinnhiem_whitelist(max_pages: int = None) -> set:
    """
    Trusted sites from /website-tin-nhiem
    ~610 pages.
    """
    print("[tinnhiemmang] Crawl trusted website list (allowlist)...")
    base = "https://tinnhiemmang.vn/website-tin-nhiem"
    domains = set()

    resp = safe_get(base)
    if resp is None:
        print("  ERROR: Cannot reach tinnhiemmang.vn")
        return domains

    pages = re.findall(r"page=(\d+)", resp.text)
    total_pages = max(int(p) for p in pages) if pages else 1
    if max_pages:
        total_pages = min(total_pages, max_pages)
    print(f"  Total pages: {total_pages}")

    domains |= _parse_tinnhiem_white_items(resp.text)

    for page in range(2, total_pages + 1):
        url = f"{base}?page={page}"
        resp = safe_get(url)
        if resp is None:
            time.sleep(DELAY)
            continue
        page_domains = _parse_tinnhiem_white_items(resp.text)
        if not page_domains:
            break
        domains |= page_domains
        if page % 50 == 0 or page == total_pages:
            print(f"  Crawled {page}/{total_pages} pages - {len(domains)} domains")
        time.sleep(DELAY)

    print(f"  => Total: {len(domains)} trusted domains from tinnhiemmang.vn")
    return domains


def _parse_tinnhiem_white_items(html: str) -> set:
    """
    Parse domain items from tinnhiemmang.vn trusted list (website-tin-nhiem).
    Structure: <a class="...webkit-box-1..." href="..."><span>domain.com </span></a>
    """
    domains = set()
    # <a class="...webkit-box-1..."> with nested <span> containing domain
    for m in re.finditer(
        r'<a[^>]*class="[^"]*webkit-box-1[^"]*"[^>]*>'
        r'\s*<span[^>]*>\s*(.*?)\s*</span>',
        html, re.DOTALL
    ):
        raw = m.group(1).strip()
        d = domain_only(raw)
        if d:
            domains.add(d)

    # fallback: direct <span class="...webkit-box-1...">
    for m in re.finditer(
        r'<span[^>]*class="[^"]*webkit-box-1[^"]*"[^>]*>\s*(.*?)\s*</span>',
        html, re.DOTALL
    ):
        raw = m.group(1).strip()
        d = domain_only(raw)
        if d and d not in domains:
            domains.add(d)

    return domains


# ============================================================
# Crawler: chongluadao.vn
# ============================================================
def crawl_chongluadao_denylist() -> set:
    """
    Denylist from /database/denylist (SSR, ~50 latest items).
    """
    print("[chongluadao] Crawl denylist (scam websites)...")
    url = "https://chongluadao.vn/database/denylist"
    resp = safe_get(url)
    if resp is None:
        print("  ERROR: Cannot reach chongluadao.vn")
        return set()
    domains = _parse_chongluadao_items(resp.text)
    print(f"  => Total: {len(domains)} domains from chongluadao denylist")
    return domains


def crawl_chongluadao_allowlist() -> set:
    """
    Allowlist from /database/allowlist (SSR, ~10 latest items).
    """
    print("[chongluadao] Crawl allowlist (safe websites)...")
    url = "https://chongluadao.vn/database/allowlist"
    resp = safe_get(url)
    if resp is None:
        print("  ERROR: Cannot reach chongluadao.vn")
        return set()
    domains = _parse_chongluadao_items(resp.text)
    print(f"  => Total: {len(domains)} domains from chongluadao allowlist")
    return domains


def _parse_chongluadao_items(html: str) -> set:
    """
    Parse URL/domain from chongluadao.vn HTML (SolidJS SSR).

    Denylist:   <span class="_urlText_1exle_106">URL</span>
    Allowlist:  <a class="_urlLink_1exle_113" href="URL">URL</a>
    Also embedded JSON: {"url":"...","domain":"...",...}
    """
    domains = set()

    # Pattern 1: <span class="_urlText_..."> (denylist)
    for m in re.finditer(r'class="_urlText_1exle_106">([^<]+)', html):
        domains.add(domain_only(m.group(1)))

    # Pattern 2: <a class="_urlLink_..."> (allowlist)
    for m in re.finditer(r'class="_urlLink_1exle_113"[^>]*>\s*([^<]+)\s*</a>', html):
        domains.add(domain_only(m.group(1)))

    # Pattern 3: JSON chunks in <script> (both lists)
    for m in re.finditer(r'\{"url":"([^"]+)"[^}]+"domain":"([^"]+)"', html):
        domains.add(domain_only(m.group(1)))
        domains.add(domain_only(m.group(2)))

    domains.discard("")
    return domains


# ============================================================
# Utility: check DNS & HTTP status of collected domains
# ============================================================
def check_domains_status(domains: set, max_workers: int = 20):
    """
    Check DNS resolution and HTTP status for a set of domains.
    Can be used to verify which scam domains are still live.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def check_one(domain: str) -> tuple:
        dns_ok = resolve_domain(domain)
        http_status = None
        if dns_ok:
            for scheme in ("https://", "http://"):
                try:
                    r = requests.get(
                        scheme + domain,
                        headers=HEADERS, timeout=10, allow_redirects=False
                    )
                    http_status = r.status_code
                    break
                except requests.RequestException:
                    continue
        return (domain, dns_ok, http_status)

    results = {"alive": [], "dead_dns": [], "dead_http": []}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check_one, d): d for d in domains}
        done = 0
        total = len(futures)
        for f in as_completed(futures):
            done += 1
            domain, dns_ok, http_status = f.result()
            if not dns_ok:
                results["dead_dns"].append(domain)
            elif http_status and http_status < 400:
                results["alive"].append((domain, http_status))
            else:
                results["dead_http"].append((domain, http_status))
            if done % 100 == 0 or done == total:
                print(f"  Checked {done}/{total}...")

    return results


# ============================================================
# Merge into existing lists
# ============================================================
def merge_into(description: str, existing_path: str, new_domains: set,
               source_tag: str):
    """Merge new domains into existing file and print summary."""
    old = read_domains(existing_path)
    before = len(old)
    old |= new_domains
    after = len(old)
    added = after - before
    write_domains(existing_path, old)

    print(f"\n{'='*50}")
    print(f"Merge result: {description}")
    print(f"  Source           : {source_tag}")
    print(f"  Newly collected  : {len(new_domains)}")
    print(f"  Newly added      : {added}")
    print(f"  Previously       : {before}")
    print(f"  Total after merge: {after}")
    print(f"  File             : {existing_path}")
    print(f"{'='*50}\n")


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="Crawl scam/legit URLs from tinnhiemmang.vn and chongluadao.vn"
    )
    parser.add_argument(
        "--source", "-s",
        choices=["tinnhiem_black", "tinnhiem_white",
                 "chongluadao_deny", "chongluadao_allow",
                 "all", "black", "white"],
        default="all",
        help="Source to crawl (default: all)"
    )
    parser.add_argument(
        "--max-pages", "-p", type=int, default=None,
        help="Limit pages (only for tinnhiemmang.vn)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Only print counts, do not write files"
    )
    parser.add_argument(
        "--no-dns-check", action="store_true",
        help="Skip DNS pre-check for target websites (not for domain list)"
    )
    parser.add_argument(
        "--check-status", nargs="?", const="black",
        choices=["black", "white", "both"],
        help="Check DNS/HTTP status of crawled domains (default: black)"
    )

    args = parser.parse_args()

    # ---- Mode: check status of existing domains ----
    if args.check_status:
        targets = []
        if args.check_status in ("black", "both"):
            targets.append((BLACK_FILE, "Blacklist"))
        if args.check_status in ("white", "both"):
            targets.append((WHITE_FILE, "Whitelist"))

        for fpath, label in targets:
            domains = read_domains(fpath)
            print(f"\n>>> Checking status: {label} ({len(domains)} domains)")
            results = check_domains_status(domains)
            print(f"\n  Results for {label}:")
            print(f"    Alive (HTTP < 400) : {len(results['alive'])}")
            print(f"    Dead DNS           : {len(results['dead_dns'])}")
            print(f"    Dead HTTP (4xx/err): {len(results['dead_http'])}")
            if results["dead_dns"]:
                print(f"    Sample dead DNS: {results['dead_dns'][:5]}")
            if results["alive"]:
                print(f"    Sample alive: {results['alive'][:5]}")
        return

    # ---- Mode: crawl ----
    tasks = []

    if args.source in ("all", "black", "tinnhiem_black"):
        tasks.append((
            crawl_tinnhiem_blacklist,
            BLACK_FILE,
            "tinnhiemmang.vn (website-lua-dao)",
            args.max_pages,
        ))
    if args.source in ("all", "white", "tinnhiem_white"):
        tasks.append((
            crawl_tinnhiem_whitelist,
            WHITE_FILE,
            "tinnhiemmang.vn (website-tin-nhiem)",
            args.max_pages,
        ))
    if args.source in ("all", "black", "chongluadao_deny"):
        tasks.append((
            crawl_chongluadao_denylist,
            BLACK_FILE,
            "chongluadao.vn (denylist)",
            None,
        ))
    if args.source in ("all", "white", "chongluadao_allow"):
        tasks.append((
            crawl_chongluadao_allowlist,
            WHITE_FILE,
            "chongluadao.vn (allowlist)",
            None,
        ))

    all_new_black = set()
    all_new_white = set()

    for func, filepath, tag, max_pg in tasks:
        print(f"\n>>> Crawling {tag} ...")
        try:
            if "tinnhiem" in tag.lower() and max_pg is not None:
                new_domains = func(max_pages=max_pg)
            else:
                new_domains = func()
        except Exception as e:
            print(f"  ERROR: {e}")
            continue

        if "black" in filepath or "deny" in tag.lower():
            all_new_black |= new_domains
        else:
            all_new_white |= new_domains

        if args.dry_run:
            print(f"  [dry-run] Would add {len(new_domains)} domains to {filepath}")
        else:
            merge_into(
                description=tag,
                existing_path=filepath,
                new_domains=new_domains,
                source_tag=tag,
            )

    if len(tasks) > 1 and not args.dry_run:
        print(f"\n{'='*50}")
        print("SUMMARY")
        print(f"  Blacklist: +{len(all_new_black)} new domains")
        print(f"  Whitelist: +{len(all_new_white)} new domains")
        print(f"{'='*50}")


if __name__ == "__main__":
    main()
