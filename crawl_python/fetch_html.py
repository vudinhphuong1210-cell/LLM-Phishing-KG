#!/usr/bin/env python3
"""
Step 1: Fetch HTML from domain lists (blacklist + whitelist).

Flow:
  Domain list → Multi-DNS check → HTTP GET → Wayback fallback → JSONL output

Output: html/raw/{blacklist,whitelist}_YYYYMMDD.jsonl
  {"url": "...", "source": "black|white", "html": "...",
   "fetched_at": "...", "method": "direct|wayback|failed",
   "status_code": 200|null, "error": null|"..."}
"""

import os
import sys
import json
import time
import logging
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import dns.resolver
from bs4 import BeautifulSoup

# Fix console encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# ── Paths ──────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
DATA_DIR = os.path.join(PROJECT_DIR, "data")
RAW_DIR = os.path.join(BASE_DIR, "html", "raw")
os.makedirs(RAW_DIR, exist_ok=True)

BLACK_FILE = os.path.join(DATA_DIR, "eval_black_list.txt")
WHITE_FILE = os.path.join(DATA_DIR, "eval_white_list.txt")

# ── Config ─────────────────────────────────────────
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )
}
HTTP_TIMEOUT = 15          # seconds per HTTP request
MAX_WORKERS = 20           # concurrent fetches
DNS_TIMEOUT = 4            # seconds per DNS query
MIN_WORDS = 50             # phishing login pages are often short

DNS_SERVERS = [
    "8.8.8.8",              # Google
    "1.1.1.1",              # Cloudflare
    "9.9.9.9",              # Quad9
    "208.67.222.222",       # OpenDNS
    "8.8.4.4",              # Google alt
]

# ── Logging ────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(BASE_DIR, "html", "fetch.log"),
            encoding="utf-8"
        )
    ]
)
log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════
#  Fix character encoding (mojibake)
# ═══════════════════════════════════════════════════
def decode_html(r: requests.Response) -> str:
    """
    Decode HTTP response to proper UTF-8 string.

    Problem: nhiều server VN gửi charset sai trong header
    (vd: Content-Type: text/html; charset=iso-8859-1) nhưng
    nội dung thực tế là UTF-8 → mojibake kiểu:
      "Má»¹ DuyÃªn" thay vì "Mỹ Duyên"

    Strategy:
      1. Thử UTF-8 trước (dùng raw bytes)
      2. Nếu lỗi → dùng encoding từ header
      3. Nếu vẫn lỗi → thử chardet detection
      4. Cuối cùng: force UTF-8 với replacement
    """
    raw = r.content

    # 1. Thử UTF-8 trực tiếp từ raw bytes
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass

    # 2. Thử encoding từ Content-Type header
    declared = r.encoding
    if declared and declared.lower() not in ("utf-8", "utf8"):
        try:
            return raw.decode(declared)
        except (UnicodeDecodeError, LookupError):
            pass

    # 3. Thử chardet nếu có
    try:
        import chardet
        detected = chardet.detect(raw)
        if detected and detected.get("encoding"):
            try:
                return raw.decode(detected["encoding"])
            except (UnicodeDecodeError, LookupError):
                pass
    except Exception:
        pass

    # 4. Common CP
    for enc in ["windows-1258", "cp1252", "iso-8859-1"]:
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue

    # 5. Force UTF-8 với replacement
    return raw.decode("utf-8", errors="replace")


def fix_mojibake(text: str) -> str:
    """
    Sửa text đã bị mojibake (garbled do sai encoding).

    Cơ chế: mojibake xảy ra khi UTF-8 bytes bị decode
    bằng Latin-1/CP1252. Fix: encode lại về bytes rồi
    decode lại bằng UTF-8.

    Dùng cho trường hợp đã lưu HTML sai từ trước,
    hoặc text đã bị hỏng qua nhiều lần xử lý.
    """
    if not text:
        return text

    # Chỉ fix nếu có dấu hiệu mojibake
    # (các ký tự Latin-1 ở vùng 0x80-0xFF xuất hiện bất thường)
    suspicious = sum(1 for c in text if "\x80" <= c <= "\xff")
    total = len(text)
    if total > 0 and suspicious / total > 0.3:
        try:
            return text.encode("latin-1").decode("utf-8", errors="replace")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass

    return text


# ═══════════════════════════════════════════════════
#  DNS resolution with multiple servers
# ═══════════════════════════════════════════════════
def resolve_multi(domain: str) -> bool:
    """
    Try multiple DNS resolvers. Return True if at least
    one A/AAAA record is found.
    """
    for ns in DNS_SERVERS:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns]
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT
            answers = resolver.resolve(domain, "A")
            if answers:
                return True
        except Exception:
            continue
    return False


# ═══════════════════════════════════════════════════
#  Wayback Machine fallback
# ═══════════════════════════════════════════════════
def fetch_wayback(domain: str) -> tuple[str | None, int | None]:
    """
    Try to get the latest page snapshot from
    archive.org Wayback Machine.

    Returns (html_content, status_code).
    """
    try:
        # Step 1: find the closest snapshot
        r = requests.get(
            f"https://archive.org/wayback/available?url={domain}",
            timeout=HTTP_TIMEOUT
        )
        data = r.json()
        snapshots = data.get("archived_snapshots", {})
        closest = snapshots.get("closest", {})
        if not closest or closest.get("status") != "200":
            return None, None

        snap_url = closest["url"]

        # Step 2: fetch the snapshot
        r2 = requests.get(snap_url, headers=HEADERS, timeout=HTTP_TIMEOUT)
        html = decode_html(r2)
        log.info(f"  Wayback OK: {domain} ({len(html)} bytes)")
        return html, 200

    except Exception as e:
        log.debug(f"  Wayback fail: {domain} — {e}")
        return None, None


# ═══════════════════════════════════════════════════
#  Helper: Word count check
# ═══════════════════════════════════════════════════
def count_words(html_content: str) -> int:
    """Extract visible text and return the word count."""
    if not html_content:
        return 0
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        # Strip script, style, and other noise tags
        strip_tags = [
            "script", "style", "nav", "footer", "header", "aside",
            "noscript", "iframe", "svg", "canvas", "button"
        ]
        for tag in soup(strip_tags):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        # Split by whitespace to count words
        words = text.split()
        return len(words)
    except Exception:
        # Fallback if parsing fails
        clean_text = re.sub(r'<[^>]+>', ' ', html_content)
        return len(clean_text.split())


# ═══════════════════════════════════════════════════
#  Fetch a single url (called concurrently)
# ═══════════════════════════════════════════════════
def fetch_one(domain: str, min_words: int = MIN_WORDS) -> dict:
    """
    Fetch HTML for one domain.

    Returns a dict ready for JSONL output.
    """
    domain = domain.strip().lower()
    # Remove protocol if accidentally included
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]
    domain = domain.split("/")[0]  # strip path
    if not domain:
        return {"url": domain, "error": "empty domain"}

    result = {
        "url": domain,
        "html": None,
        "fetched_at": datetime.utcnow().isoformat(),
        "method": None,
        "status_code": None,
        "error": None,
    }

    # ── DNS check ──
    dns_ok = resolve_multi(domain)

    # ── Direct HTTP fetch ──
    if dns_ok:
        for scheme in ("https://", "http://"):
            try:
                r = requests.get(
                    scheme + domain,
                    headers=HEADERS,
                    timeout=HTTP_TIMEOUT,
                    allow_redirects=True,
                )
                # Giải mã encoding một cách thông minh
                html = decode_html(r)

                result["status_code"] = r.status_code
                if r.status_code < 400:
                    result["html"] = html
                    result["method"] = "direct"
                    break
                elif r.status_code in (429, 503):
                    # Rate-limited / temporary — retry once
                    time.sleep(2)
                    r2 = requests.get(
                        scheme + domain,
                        headers=HEADERS,
                        timeout=HTTP_TIMEOUT,
                    )
                    html2 = decode_html(r2)
                    result["status_code"] = r2.status_code
                    if r2.status_code < 400:
                        result["html"] = html2
                        result["method"] = "direct"
                        break
            except requests.ConnectionError:
                continue
            except requests.Timeout:
                continue
            except Exception as e:
                log.debug(f"  HTTP err {domain}: {e}")
                continue

    # ── Wayback fallback ──
    if result["html"] is None:
        html, code = fetch_wayback(domain)
        if html:
            result["html"] = html
            result["method"] = "wayback"
            result["status_code"] = code

    # Keep compact login/form pages. Many phishing pages are much shorter than
    # normal content pages, so a hard 500-word cutoff drops useful evidence.
    if result["html"] is not None:
        word_count = count_words(result["html"])
        has_form_signal = bool(re.search(r"<form\b|type=[\"']?password", result["html"], re.IGNORECASE))
        if word_count < min_words and not has_form_signal:
            result["html"] = None
            result["method"] = "failed"
            result["error"] = f"HTML content too short ({word_count} words, minimum required is {min_words})"

    # ── Mark as failed ──
    if result["html"] is None and result["error"] is None:
        result["method"] = "failed"
        result["error"] = "DNS fail + no Wayback snapshot"

    return result


# ═══════════════════════════════════════════════════
#  Read domain lists
# ═══════════════════════════════════════════════════
def load_domains(path: str) -> list[str]:
    """Read domain file, return list of non-empty lines."""
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


# ═══════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════
def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Step 1: Fetch HTML from domain lists"
    )
    parser.add_argument(
        "--source", "-s",
        choices=["black", "white", "both"],
        default="both",
        help="Which list to crawl (default: both)"
    )
    parser.add_argument(
        "--limit", "-n", type=int, default=None,
        help="Limit number of domains to fetch (for testing)"
    )
    parser.add_argument(
        "--workers", "-w", type=int, default=MAX_WORKERS,
        help=f"Concurrent workers (default: {MAX_WORKERS})"
    )
    parser.add_argument(
        "--fix-mojibake", action="store_true",
        help="Force fix mojibake on already-fetched JSONL files"
    )
    parser.add_argument(
        "--min-words", type=int, default=MIN_WORDS,
        help=f"Minimum visible words for pages without form/login evidence (default: {MIN_WORDS})"
    )

    args = parser.parse_args()

    # ── Mode: fix mojibake on existing files ──
    if args.fix_mojibake:
        log.info("=== Fix mojibake on existing JSONL files ===")
        for fname in sorted(os.listdir(RAW_DIR)):
            if not fname.endswith(".jsonl"):
                continue
            fpath = os.path.join(RAW_DIR, fname)
            log.info(f"Processing: {fname}")

            fixed_count = 0
            out_lines = []
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        out_lines.append(line)
                        continue

                    html = rec.get("html")
                    if html:
                        fixed = fix_mojibake(html)
                        if fixed != html:
                            rec["html"] = fixed
                            rec["_mojibake_fixed"] = True
                            fixed_count += 1
                    out_lines.append(json.dumps(rec, ensure_ascii=False))

            log.info(f"  Fixed {fixed_count} records")
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("\n".join(out_lines) + "\n")
        return

    # ── Gather domains ──
    sources = []
    if args.source in ("black", "both"):
        sources.append(("black", BLACK_FILE))
    if args.source in ("white", "both"):
        sources.append(("white", WHITE_FILE))

    for label, filepath in sources:
        domains = load_domains(filepath)
        if args.limit:
            domains = domains[:args.limit]

        log.info(f"[{label}] Start fetching {len(domains)} domains...")

        # Tạo đường dẫn lưu file trước khi chạy
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(RAW_DIR, f"{label}list_{date_str}.jsonl")

        done = 0
        successes = 0
        start_time = time.time()

        # Mở file ghi trực tiếp từng dòng (incremental checkpoint)
        with open(out_path, "w", encoding="utf-8") as f_out:
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures = {pool.submit(fetch_one, d, args.min_words): d for d in domains}
                total = len(futures)

                try:
                    for future in as_completed(futures):
                        done += 1
                        domain = futures[future]
                        try:
                            res = future.result()
                            res["source"] = label
                        except Exception as e:
                            res = {
                                "url": domain,
                                "source": label,
                                "html": None,
                                "fetched_at": datetime.utcnow().isoformat(),
                                "method": "failed",
                                "status_code": None,
                                "error": str(e),
                            }

                        if res.get("html"):
                            successes += 1

                        # Ghi thẳng xuống đĩa
                        f_out.write(json.dumps(res, ensure_ascii=False) + "\n")

                        # Flush dữ liệu định kỳ sau mỗi 10 tên miền để đảm bảo an toàn
                        if done % 10 == 0 or done == total:
                            f_out.flush()

                        if done % 50 == 0 or done == total:
                            elapsed = time.time() - start_time
                            rate = done / elapsed if elapsed > 0 else 0
                            log.info(
                                f"  [{label}] {done}/{total} "
                                f"({successes} OK, {rate:.1f} dom/s)"
                            )
                except KeyboardInterrupt:
                    log.warning(f"\n[KeyboardInterrupt] Đã dừng giữa chừng! Tiến trình lưu tại: {out_path}")
                    try:
                        pool.shutdown(wait=False, cancel_futures=True)
                    except TypeError:
                        pool.shutdown(wait=False)
                    log.info(f"Đã lưu thành công {done} tên miền đầu tiên.")
                    sys.exit(0)

        log.info(
            f"[{label}] Done: {successes}/{len(domains)} fetched "
            f"({len(domains) - successes} failed)"
        )
        log.info(f"  Saved → {out_path}")

    log.info("Done.")


if __name__ == "__main__":
    main()
