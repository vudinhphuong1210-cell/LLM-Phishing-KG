#!/usr/bin/env python3
"""
Step 2: Extract clean text from raw HTML (JSONL files).

Flow:
  html/raw/{black,white}list_*.jsonl
    → BeautifulSoup parse
    → Strip script/style/nav/footer/header
    → Extract title, meta, visible text, forms, links
    → html/processed/{black,white}list_text_*.jsonl

Output JSONL format:
  {"url": "...", "source": "black|white",
   "title": "...", "meta_description": "...",
   "text": "...", "text_length": 1234,
   "forms_count": 2, "has_password_field": true,
   "external_links": ["https://..."],
   "links_to_domains": ["other.com"],
   "method": "direct|wayback",
   "fetched_at": "..."}
"""

import os
import sys
import json
import re
import logging
from datetime import datetime
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Comment

# Fix console encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# ── Paths ──────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(BASE_DIR, "html", "raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "html", "processed")
os.makedirs(PROCESSED_DIR, exist_ok=True)

# ── Logging ────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(BASE_DIR, "html", "extract.log"),
            encoding="utf-8"
        )
    ]
)
log = logging.getLogger(__name__)

# ── Tags to strip entirely ─────────────────────────
STRIP_TAGS = {
    "script", "style", "nav", "footer", "header", "aside",
    "noscript", "iframe", "svg", "canvas",
    "button", "select", "option", "input", "textarea",
}

# ── Common noise patterns ──────────────────────────
NOISE_PATTERNS = [
    r"©\s*\d{4}.*",
    r"All\s+rights?\s+reserved",
    r"Đã\s+xem\s*:\s*\d+",
    r"Lượt\s+xem\s*:\s*\d+",
    r"cookie",
    r"Chấp\s+nhận\s+(tất\s+cả\s+)?cookie",
    r"Accept\s+(all\s+)?cookies",
    r"bản\s+quyền\s+thuộc\s+về",
    r"copyright\s+by",
]


# ═══════════════════════════════════════════════════
#  Fix mojibake (encoding repair)
# ═══════════════════════════════════════════════════
def fix_mojibake(text: str) -> str:
    """
    Detect and fix mojibake: UTF-8 bytes wrongly decoded as Latin-1.

    Ví dụ: "Má»¹ DuyÃªn" → "Mỹ Duyên"
           "nHiá»n Há»" → "Hiền Hồ"

    Chỉ fix nếu >30% ký tự nằm ở vùng Latin-1 mở rộng
    (0x80-0xFF) — dấu hiệu điển hình của mojibake.
    """
    if not text or len(text) < 10:
        return text

    # Đếm ký tự ở vùng Latin-1 Extended (0x80-0xFF)
    suspicious = sum(1 for c in text if "\x80" <= c <= "\xff")
    total = len(text)
    ratio = suspicious / total

    # Nếu >30% là suspicious → khả năng cao bị mojibake
    if ratio > 0.30:
        try:
            fixed = text.encode("latin-1").decode("utf-8", errors="replace")
            return fixed
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass

    return text


# ═══════════════════════════════════════════════════
#  Text cleaning
# ═══════════════════════════════════════════════════
def collapse_whitespace(text: str) -> str:
    """Collapse multiple spaces/newlines into single space."""
    text = re.sub(r"[\r\n]+", " ", text)
    text = re.sub(r" {2,}", " ", text)
    return text.strip()


def is_noise_line(line: str) -> bool:
    """Check if a line matches known noise patterns."""
    for pat in NOISE_PATTERNS:
        if re.search(pat, line, re.IGNORECASE):
            return True
    stripped = line.strip()
    if len(stripped) < 3:
        return True
    alpha_ratio = sum(c.isalpha() for c in stripped) / max(len(stripped), 1)
    return alpha_ratio < 0.3


def clean_text(text: str) -> str:
    """Final cleaning pass on extracted text."""
    lines = text.split("\n")
    cleaned = []
    for line in lines:
        line = line.strip()
        if not line or is_noise_line(line):
            continue
        cleaned.append(line)
    return "\n".join(cleaned)


# ═══════════════════════════════════════════════════
#  HTML → structured data
# ═══════════════════════════════════════════════════
def extract_one(record: dict) -> dict:
    """
    Parse HTML from a raw JSONL record,
    return processed record with clean text + features.
    """
    url = record.get("url", "")
    html = record.get("html")
    source = record.get("source", "unknown")

    result = {
        "url": url,
        "source": source,
        "title": None,
        "meta_description": None,
        "text": None,
        "text_length": 0,
        "forms_count": 0,
        "has_password_field": False,
        "external_links": [],
        "links_to_domains": [],
        "method": record.get("method"),
        "fetched_at": record.get("fetched_at"),
        "screenshot_path": record.get("screenshot_path"),
        "error": None,
    }

    if not html:
        result["error"] = "no html content"
        return result

    # Fix mojibake trước khi parse và theo dõi cờ
    fixed_html = fix_mojibake(html)
    result["_mojibake_fixed"] = (fixed_html != html)
    html = fixed_html

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception as e:
        result["error"] = f"parse error: {e}"
        return result

    # ── Title ──
    title_tag = soup.find("title")
    if title_tag:
        result["title"] = collapse_whitespace(title_tag.get_text())

    # ── Meta description ──
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc:
        result["meta_description"] = meta_desc.get("content", "").strip()

    # ── Forms ──
    forms = soup.find_all("form")
    result["forms_count"] = len(forms)
    for form in forms:
        pw = form.find("input", attrs={"type": "password"})
        if pw:
            result["has_password_field"] = True

    # ── External links ──
    links = []
    link_domains = set()
    parsed_url = urlparse(f"https://{url}") if "://" not in url else urlparse(url)

    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].strip()
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        if not href.startswith(("http://", "https://")):
            continue

        links.append(href)
        link_domain = urlparse(href).netloc.lower()
        if link_domain and link_domain != parsed_url.netloc:
            if link_domain.startswith("www."):
                link_domain = link_domain[4:]
            link_domains.add(link_domain)

    result["external_links"] = links[:50]
    result["links_to_domains"] = sorted(link_domains)

    # ── Visible text ──
    for tag_name in STRIP_TAGS:
        for tag in soup.find_all(tag_name):
            tag.decompose()

    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comment.extract()

    for tag in soup.find_all(style=re.compile(r"display\s*:\s*none", re.I)):
        tag.decompose()
    for tag in soup.find_all(hidden=True):
        tag.decompose()

    text = soup.get_text(separator="\n", strip=True)
    text = clean_text(text)

    result["text"] = text
    result["text_length"] = len(text)

    return result


def worker_task(line_str):
    """Worker task at module level to make it pickleable on Windows."""
    try:
        record = json.loads(line_str)
        res = extract_one(record)
        return res, None
    except Exception as ex:
        return None, ex


# ═══════════════════════════════════════════════════
#  Find input files
# ═══════════════════════════════════════════════════
def find_raw_files() -> list[tuple[str, str]]:
    """Scan html/raw/ for JSONL files."""
    files = []
    if not os.path.isdir(RAW_DIR):
        return files
    for fname in sorted(os.listdir(RAW_DIR)):
        if not fname.endswith(".jsonl"):
            continue
        path = os.path.join(RAW_DIR, fname)
        if "black" in fname:
            files.append(("black", path))
        elif "white" in fname:
            files.append(("white", path))
        else:
            files.append(("unknown", path))
    return files


# ═══════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════
def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Step 2: Extract clean text from raw HTML"
    )
    parser.add_argument(
        "--input", "-i", type=str, default=None,
        help="Specific input file (default: latest in html/raw/)"
    )
    parser.add_argument(
        "--source", "-s", choices=["black", "white", "both"],
        default="both",
        help="Which list to process (default: both)"
    )
    parser.add_argument(
        "--limit", "-n", type=int, default=None,
        help="Limit records to process (for testing)"
    )

    args = parser.parse_args()

    if args.input:
        in_files = [("custom", args.input)]
    else:
        in_files = find_raw_files()

    in_files = [(l, p) for l, p in in_files
                 if args.source == "both" or l == args.source]

    if not in_files:
        log.error("No input files found in html/raw/")
        log.info("Run fetch_html.py first or specify --input")
        sys.exit(1)

    for label, in_path in in_files:
        log.info(f"[{label}] Processing: {in_path}")

        # Đọc toàn bộ các dòng hợp lệ từ file đầu vào
        records = []
        with open(in_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(line)
                    
        total = len(records)
        if args.limit:
            records = records[:args.limit]
            total = len(records)

        log.info(f"  Records to process: {total}")

        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_name = f"{label}list_text_{date_str}.jsonl"
        out_path = os.path.join(PROCESSED_DIR, out_name)

        processed = 0
        errors = 0
        mojibake_fixed = 0



        from concurrent.futures import ProcessPoolExecutor, as_completed
        # Dùng ProcessPoolExecutor vì BS4 parsing là CPU-bound (GIL bottleneck)
        # Sử dụng tối đa số CPU cores hiện có
        with open(out_path, "w", encoding="utf-8") as fout:
            num_workers = max(1, os.cpu_count() - 1) if os.cpu_count() else 1
            log.info(f"  Starting ProcessPoolExecutor with {num_workers} workers to prevent RAM exhaustion.")
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                futures = {executor.submit(worker_task, line): i for i, line in enumerate(records)}
                
                # as_completed không đảm bảo thứ tự ban đầu, nhưng tối ưu thông lượng tốt nhất
                for future in as_completed(futures):
                    line_idx = futures[future]
                    try:
                        result, err = future.result()
                        if err is not None:
                            log.warning(f"  Line {line_idx}: processing error — {err}")
                            errors += 1
                            continue
                            
                        if result.get("error"):
                            errors += 1
                        if result.get("_mojibake_fixed"):
                            mojibake_fixed += 1
                            
                        fout.write(json.dumps(result, ensure_ascii=False) + "\n")
                        processed += 1
                    except Exception as e:
                        log.warning(f"  Line {line_idx}: unexpected exception — {e}")
                        errors += 1

                    if processed % 100 == 0 or processed == total:
                        log.info(
                            f"  [{label}] {processed}/{total} processed "
                            f"({errors} errors, {mojibake_fixed} mojibake)"
                        )

        log.info(
            f"[{label}] Done: {processed} processed, "
            f"{errors} errors, {mojibake_fixed} mojibake fixed"
        )
        log.info(f"  Saved → {out_path}")

    log.info("Done.")


if __name__ == "__main__":
    main()
