#!/usr/bin/env python3
"""
Step 1.5: Làm sạch file JSONL raw từ fetch_html.py trước khi extract_text.py.

Mục đích:
  - Loại bỏ các bản ghi failed (html = null)
  - Loại bỏ các bản ghi trùng lặp (cùng URL)
  - Loại bỏ các bản ghi HTML quá ngắn (< MIN_WORDS từ)
  - Loại bỏ các bản ghi HTML chỉ là error page / parking page
  - In thống kê chi tiết sau khi lọc
  - Xuất file mới (không overwrite, giữ nguyên file gốc)

Flow:
  html/raw/{black,white}list_YYYYMMDD.jsonl  (raw, dirty)
    → filter failed
    → dedup by url
    → filter low-quality HTML
    → html/raw/{black,white}list_YYYYMMDD_cleaned.jsonl  (clean)

Usage:
  python clean_blacklist.py                           # tất cả file trong html/raw/
  python clean_blacklist.py -i html/raw/blacklist_20260607_205540.jsonl
  python clean_blacklist.py -s black                  # chỉ xử lý blacklist
  python clean_blacklist.py --min-words 300           # tùy chỉnh ngưỡng từ
  python clean_blacklist.py --dry-run                 # chỉ thống kê, không ghi file
"""

import os
import sys
import re
import json
import logging
import argparse
from datetime import datetime

from bs4 import BeautifulSoup

# ── Paths ──────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_DIR  = os.path.join(BASE_DIR, "html", "raw")

# Đảm bảo Python có thể import từ core và infrastructure
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from infrastructure.sqlite_deduplicator import SqliteDeduplicator

# Fix console encoding cho Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# ── Default config ─────────────────────────────────────────────────────
MIN_WORDS         = 200     # ngưỡng tối thiểu từ visible text
MAX_HTML_SIZE_MB  = 10      # bỏ qua HTML > 10 MB (bất thường)

# Các pattern nhận biết parking / error page
PARKING_PATTERNS = [
    r"domain\s+(is|has been)\s+(parked|for sale|expired)",
    r"this\s+domain\s+is\s+(available|for\s+sale)",
    r"buy\s+this\s+domain",
    r"sedoparking|sedo\.com",
    r"godaddy\s+parked",
    r"this\s+page\s+is\s+not\s+found",
    r"404\s+(not\s+found|error)",
    r"403\s+(forbidden|error)",
    r"access\s+denied",
    r"website\s+coming\s+soon",
    r"under\s+construction",
    r"trang\s+web\s+(đang\s+xây\s+dựng|không\s+tồn\s+tại|không\s+tìm\s+thấy)",
    r"tên\s+miền\s+này\s+(đã\s+hết\s+hạn|chưa\s+được\s+kích\s+hoạt)",
]

# ── Logging ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(BASE_DIR, "html", "clean.log"),
            encoding="utf-8"
        )
    ]
)
log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════
def count_visible_words(html_content: str) -> int:
    """Đếm số từ visible text sau khi strip script/style/nav/footer."""
    if not html_content:
        return 0
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        strip_tags = [
            "script", "style", "nav", "footer", "header", "aside",
            "noscript", "iframe", "svg", "canvas", "button",
        ]
        for tag in soup(strip_tags):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        return len(text.split())
    except Exception:
        # Fallback: strip HTML bằng regex
        clean = re.sub(r"<[^>]+>", " ", html_content)
        return len(clean.split())


def is_parking_page(html_content: str) -> bool:
    """
    Phát hiện parking page / error page thông qua visible text.
    Kiểm tra nhanh bằng regex trên text (không parse full HTML).
    """
    if not html_content:
        return False
    # Chỉ kiểm tra 5000 ký tự đầu để nhanh
    sample = html_content[:5000].lower()
    for pat in PARKING_PATTERNS:
        if re.search(pat, sample, re.IGNORECASE):
            return True
    return False


def is_too_large(html_content: str) -> bool:
    """Kiểm tra HTML có vượt giới hạn kích thước không."""
    return len(html_content.encode("utf-8", errors="replace")) > MAX_HTML_SIZE_MB * 1024 * 1024


# ═══════════════════════════════════════════════════════════════════════
#  Core: clean one JSONL file
# ═══════════════════════════════════════════════════════════════════════
def clean_file(
    in_path: str,
    deduplicator=None,
    min_words: int = MIN_WORDS,
    dry_run: bool = False,
) -> dict:
    """
    Đọc 1 file JSONL raw, lọc và ghi ra file *_cleaned.jsonl.

    Returns dict thống kê.
    """
    stats = {
        "file": os.path.basename(in_path),
        "total":          0,
        "kept":           0,
        "failed_html":    0,   # html = null
        "duplicate_url":  0,   # URL trùng
        "too_large":      0,   # HTML > MAX_HTML_SIZE_MB
        "too_short":      0,   # < min_words
        "parking_page":   0,   # parking/error page
        "cross_filtered": 0,   # Lọc chéo blacklist/whitelist
    }

    if not os.path.exists(in_path):
        log.error(f"File không tồn tại: {in_path}")
        return stats

    # Xác định output path
    base, ext = os.path.splitext(in_path)
    # Nếu đã có _cleaned thì không thêm lần nữa
    if base.endswith("_cleaned"):
        out_path = in_path
    else:
        out_path = base + "_cleaned" + ext

    # Xác định loại kiểm tra chéo (cross check)
    fname = os.path.basename(in_path).lower()
    is_blacklist_file = "blacklist" in fname
    is_whitelist_file = "whitelist" in fname

    log.info(f"Input  : {in_path}")
    if not dry_run:
        log.info(f"Output : {out_path}")
    else:
        log.info("Chế độ: DRY RUN (không ghi file)")

    if not dry_run:
        f_out = open(out_path, "w", encoding="utf-8", buffering=1024*1024)
    else:
        f_out = None

    with open(in_path, "r", encoding="utf-8") as f:
        batch_urls = []
        batch_recs = []
        
        def flush_batch():
            if not batch_urls:
                return
            
            # 1. Thực hiện lọc chéo (Cross filter) trước để loại bỏ các URL thuộc tập đối nghịch
            cross_filtered_urls = []
            if deduplicator:
                if is_blacklist_file:
                    # Nếu là file blacklist, loại bỏ các URL đã có trong whitelist database
                    whitelisted = deduplicator.get_existing_in_list(batch_urls, "whitelist")
                    for u in batch_urls:
                        if u in whitelisted:
                            log.warning(f"  [cross-filter] URL {u} đã bị Whitelisted, loại khỏi blacklist!")
                            stats["cross_filtered"] += 1
                        else:
                            cross_filtered_urls.append(u)
                elif is_whitelist_file:
                    # Nếu là file whitelist, loại bỏ các URL đã có trong blacklist database
                    blacklisted = deduplicator.get_existing_in_list(batch_urls, "blacklist")
                    for u in batch_urls:
                        if u in blacklisted:
                            log.warning(f"  [cross-filter] URL {u} đã bị Blacklisted, loại khỏi whitelist!")
                            stats["cross_filtered"] += 1
                        else:
                            cross_filtered_urls.append(u)
                else:
                    cross_filtered_urls = batch_urls
            else:
                cross_filtered_urls = batch_urls

            if not cross_filtered_urls:
                batch_urls.clear()
                batch_recs.clear()
                return

            # 2. Kiểm tra trùng lặp (Deduplication) qua SQLite
            new_urls_list = []
            if deduplicator:
                new_urls_list = deduplicator.filter_and_add_batch(cross_filtered_urls, list_type="raw_html", read_only=dry_run)
                stats["duplicate_url"] += len(cross_filtered_urls) - len(new_urls_list)
            else:
                new_urls_list = cross_filtered_urls
                
            new_urls_set = set(new_urls_list)
            
            # Chỉ xử lý các record có URL lọt qua bộ lọc
            for b_url, b_rec in zip(batch_urls, batch_recs):
                if b_url not in new_urls_set:
                    continue
                    
                html = b_rec.get("html")
                
                # ── 3. Loại bỏ HTML quá lớn ────────────────────────────
                if is_too_large(html):
                    log.debug(f"  Too large: {b_url}")
                    stats["too_large"] += 1
                    continue

                # ── 4. Loại bỏ parking/error page ──────────────────────
                if is_parking_page(html):
                    log.debug(f"  Parking page: {b_url}")
                    stats["parking_page"] += 1
                    continue

                # ── 5. Loại bỏ HTML có quá ít từ ───────────────────────
                word_count = count_visible_words(html)
                if word_count < min_words:
                    log.debug(f"  Too short ({word_count} words): {b_url}")
                    stats["too_short"] += 1
                    continue

                # ── Pass: giữ lại bản ghi này ──────────────────────────
                stats["kept"] += 1
                if f_out is not None:
                    f_out.write(json.dumps(b_rec, ensure_ascii=False) + "\n")
                    
            batch_urls.clear()
            batch_recs.clear()

        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            stats["total"] += 1

            # ── Parse JSON ──────────────────────────────────────────
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                log.warning(f"  Line {line_no}: JSON decode error — {e}")
                stats["failed_html"] += 1
                continue

            url  = rec.get("url", "").strip().lower()
            html = rec.get("html")

            # ── 1. Loại bỏ html = null ──────────────────────────────
            if not html:
                stats["failed_html"] += 1
                continue
                
            batch_urls.append(url)
            batch_recs.append(rec)
            
            # Kích hoạt flush mỗi khi gom đủ 100 records (cân bằng RAM và Disk I/O)
            if len(batch_urls) >= 100:
                flush_batch()
                
            # Progress mỗi 500 bản ghi
            if stats["total"] % 500 == 0:
                if f_out is not None:
                    f_out.flush()
                log.info(
                    f"  Đã xử lý {stats['total']} | "
                    f"giữ {stats['kept']} | "
                    f"loại {stats['total'] - stats['kept']}"
                )

        # Xử lý nốt batch cuối cùng
        flush_batch()

    # ── Đóng file output ───────────────────────────────────────────────
    if f_out is not None:
        f_out.flush()
        f_out.close()
        log.info(f"  Đã ghi {stats['kept']} bản ghi → {out_path}")

    return stats


# ═══════════════════════════════════════════════════════════════════════
#  Print summary
# ═══════════════════════════════════════════════════════════════════════
def print_stats(stats: dict):
    total    = stats["total"]
    kept     = stats["kept"]
    removed  = total - kept
    pct_kept = (kept / total * 100) if total > 0 else 0

    log.info(f"\n{'='*54}")
    log.info(f"  KẾT QUẢ LỌC: {stats['file']}")
    log.info(f"{'='*54}")
    log.info(f"  Tổng bản ghi đọc       : {total:>7,}")
    log.info(f"  Giữ lại (sạch)         : {kept:>7,}  ({pct_kept:.1f}%)")
    log.info(f"  Loại bỏ (tổng)         : {removed:>7,}")
    log.info(f"    ├─ HTML null/lỗi     : {stats['failed_html']:>7,}")
    log.info(f"    ├─ Kiểm tra chéo (đối nghịch) : {stats.get('cross_filtered', 0):>7,}")
    log.info(f"    ├─ URL trùng lặp     : {stats['duplicate_url']:>7,}")
    log.info(f"    ├─ HTML quá lớn      : {stats['too_large']:>7,}")
    log.info(f"    ├─ Parking/Error page: {stats['parking_page']:>7,}")
    log.info(f"    └─ Ít từ (< {stats.get('min_words', MIN_WORDS)} từ) : {stats['too_short']:>7,}")
    log.info(f"{'='*54}")


# ═══════════════════════════════════════════════════════════════════════
#  Find files in RAW_DIR
# ═══════════════════════════════════════════════════════════════════════
def find_raw_files(source: str) -> list[str]:
    """
    Tìm tất cả *.jsonl trong html/raw/ theo filter source.
    Bỏ qua các file *_cleaned.jsonl.
    """
    files = []
    if not os.path.isdir(RAW_DIR):
        return files
    for fname in sorted(os.listdir(RAW_DIR)):
        if not fname.endswith(".jsonl"):
            continue
        if "_cleaned" in fname:
            continue  # bỏ qua file đã clean rồi
        if source == "black" and "black" not in fname:
            continue
        if source == "white" and "white" not in fname:
            continue
        files.append(os.path.join(RAW_DIR, fname))
    return files


# ═══════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="Step 1.5: Lọc và làm sạch file JSONL raw từ fetch_html.py"
    )
    parser.add_argument(
        "--input", "-i", type=str, default=None,
        help="Đường dẫn file JSONL cụ thể (mặc định: tất cả file trong html/raw/)"
    )
    parser.add_argument(
        "--source", "-s",
        choices=["black", "white", "both"],
        default="both",
        help="Chỉ xử lý blacklist hoặc whitelist (mặc định: both)"
    )
    parser.add_argument(
        "--min-words", type=int, default=MIN_WORDS,
        help=f"Ngưỡng từ tối thiểu (mặc định: {MIN_WORDS})"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Chỉ thống kê, không ghi file output"
    )

    args = parser.parse_args()

    db_path = os.path.join(BASE_DIR, "..", "data", "dedup_cache.db")
    dedup = SqliteDeduplicator(os.path.abspath(db_path))

    # ── Xác định danh sách file cần xử lý ──────────────────────────
    if args.input:
        if not os.path.isabs(args.input):
            # Thử resolve relative path từ BASE_DIR
            candidate = os.path.join(BASE_DIR, args.input)
            if os.path.exists(candidate):
                args.input = candidate
        files = [args.input]
    else:
        files = find_raw_files(args.source)

    if not files:
        log.error("Không tìm thấy file JSONL nào để xử lý.")
        log.info(f"  Thư mục tìm kiếm: {RAW_DIR}")
        log.info("  Hãy chạy fetch_html.py trước hoặc dùng --input để chỉ định file.")
        sys.exit(1)

    log.info(f"Tìm thấy {len(files)} file cần xử lý:")
    for f in files:
        size_mb = os.path.getsize(f) / 1024 / 1024
        log.info(f"  {os.path.basename(f)}  ({size_mb:.1f} MB)")

    # ── Xử lý từng file ────────────────────────────────────────────
    all_stats = []
    for fpath in files:
        log.info(f"\n{'─'*54}")
        log.info(f"Đang xử lý: {os.path.basename(fpath)}")
        log.info(f"{'─'*54}")

        stats = clean_file(
            in_path=fpath,
            deduplicator=dedup,
            min_words=args.min_words,
            dry_run=args.dry_run,
        )
        stats["min_words"] = args.min_words
        all_stats.append(stats)
        print_stats(stats)

    # ── Tổng hợp nếu nhiều file ────────────────────────────────────
    if len(all_stats) > 1:
        grand_total = sum(s["total"] for s in all_stats)
        grand_kept  = sum(s["kept"]  for s in all_stats)
        log.info(f"\n{'='*54}")
        log.info("  TỔNG KẾT TẤT CẢ FILES")
        log.info(f"{'='*54}")
        log.info(f"  Tổng bản ghi          : {grand_total:>7,}")
        log.info(f"  Tổng giữ lại          : {grand_kept:>7,}  ({grand_kept/grand_total*100:.1f}%)")
        log.info(f"  Tổng loại bỏ          : {grand_total - grand_kept:>7,}")
        log.info(f"{'='*54}")

    log.info("\nHoàn thành. Bước tiếp theo: chạy extract_text.py trên file *_cleaned.jsonl")


if __name__ == "__main__":
    main()
