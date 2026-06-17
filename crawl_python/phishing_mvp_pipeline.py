#!/usr/bin/env python3
"""Offline-first dataset pipeline for Vietnamese phishing URL research."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
DATA_DIR = PROJECT_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
HTML_DATA_DIR = DATA_DIR / "html"
SCREENSHOT_DIR = DATA_DIR / "screenshots"
FEATURE_DIR = DATA_DIR / "features"
PROCESSED_DIR = DATA_DIR / "processed"
REPORT_DIR = PROJECT_DIR / "reports"
CONFIG_DIR = PROJECT_DIR / "configs"

BRAND_CATALOG = BASE_DIR / "brand_catalog.json"
BLACK_FILE = DATA_DIR / "eval_black_list.txt"
WHITE_FILE = DATA_DIR / "eval_white_list.txt"
CRAWL_RAW_DIR = BASE_DIR / "html" / "raw"
CRAWL_PROCESSED_DIR = BASE_DIR / "html" / "processed"

SUSPICIOUS_TOKENS = {
    "login", "signin", "verify", "verification", "account", "secure", "security",
    "support", "update", "confirm", "otp", "wallet", "bank", "bonus", "gift",
    "khuyenmai", "khuyen-mai", "nhanqua", "nhan-qua", "xacthuc", "xac-thuc",
    "dangnhap", "dang-nhap", "taikhoan", "tai-khoan", "hoantien", "hoan-tien",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_dirs() -> None:
    for path in [
        RAW_DATA_DIR, HTML_DATA_DIR, SCREENSHOT_DIR, FEATURE_DIR,
        PROCESSED_DIR, REPORT_DIR, CONFIG_DIR,
        CRAWL_RAW_DIR, CRAWL_PROCESSED_DIR,
    ]:
        path.mkdir(parents=True, exist_ok=True)


def normalize_domain(value: str) -> str:
    value = (value or "").strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = "http://" + value
    parsed = urlparse(value)
    host = parsed.netloc or parsed.path.split("/")[0]
    host = host.split("@")[-1].split(":")[0].strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def canonical_url(value: str) -> str:
    value = (value or "").strip()
    return value if "://" in value else "http://" + value


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def load_brands() -> list[dict]:
    if not BRAND_CATALOG.exists():
        return []
    with BRAND_CATALOG.open("r", encoding="utf-8") as f:
        catalog = json.load(f)
    brands = []
    for category, items in catalog.items():
        if category.startswith("_") or not isinstance(items, list):
            continue
        for item in items:
            copied = dict(item)
            copied["category"] = category
            brands.append(copied)
    return brands


def remove_vietnamese_accents(text: str) -> str:
    """Removes Vietnamese accents while keeping characters in ASCII format."""
    if not text:
        return ""
    # Chuẩn hóa Unicode sang dạng NFC để đảm bảo nhất quán các ký tự ghép dấu
    text = unicodedata.normalize('NFC', text)
    
    mapping = {
        'à': 'a', 'á': 'a', 'ả': 'a', 'ã': 'a', 'ạ': 'a',
        'ă': 'a', 'ằ': 'a', 'ắ': 'a', 'ẳ': 'a', 'ẵ': 'a', 'ặ': 'a',
        'â': 'a', 'ầ': 'a', 'ấ': 'a', 'ẩ': 'a', 'ẫ': 'a', 'ậ': 'a',
        'đ': 'd',
        'è': 'e', 'é': 'e', 'ẻ': 'e', 'ẽ': 'e', 'ẹ': 'e',
        'ê': 'e', 'ề': 'e', 'ế': 'e', 'ể': 'e', 'ễ': 'e', 'ệ': 'e',
        'ì': 'i', 'í': 'i', 'ỉ': 'i', 'ĩ': 'i', 'ị': 'i',
        'ò': 'o', 'ó': 'o', 'ỏ': 'o', 'õ': 'o', 'ọ': 'o',
        'ô': 'o', 'ồ': 'o', 'ố': 'o', 'ổ': 'o', 'ỗ': 'o', 'ộ': 'o',
        'ơ': 'o', 'ờ': 'o', 'ớ': 'o', 'ở': 'o', 'ỡ': 'o', 'ợ': 'o',
        'ù': 'u', 'ú': 'u', 'ủ': 'u', 'ũ': 'u', 'ụ': 'u',
        'ư': 'u', 'ừ': 'u', 'ứ': 'u', 'ử': 'u', 'ữ': 'u', 'ự': 'u',
        'ỳ': 'y', 'ý': 'y', 'ỷ': 'y', 'ỹ': 'y', 'ỵ': 'y',
        'À': 'A', 'Á': 'A', 'Ả': 'A', 'Ã': 'A', 'Ạ': 'A',
        'Ă': 'A', 'Ằ': 'A', 'Ắ': 'A', 'Ẳ': 'A', 'Ẵ': 'A', 'Ặ': 'A',
        'Â': 'A', 'Ầ': 'A', 'Ấ': 'A', 'Ẩ': 'A', 'Ẫ': 'A', 'Ậ': 'A',
        'Đ': 'D',
        'È': 'E', 'É': 'E', 'Ẻ': 'E', 'Ẽ': 'E', 'Ẹ': 'E',
        'Ê': 'E', 'Ề': 'E', 'Ế': 'E', 'Ể': 'E', 'Ễ': 'E', 'Ệ': 'E',
        'Ì': 'I', 'Í': 'I', 'Ỉ': 'I', 'Ĩ': 'I', 'Ị': 'I',
        'Ò': 'O', 'Ó': 'O', 'Ỏ': 'O', 'Õ': 'O', 'Ọ': 'O',
        'Ô': 'O', 'Ồ': 'O', 'Ố': 'O', 'Ổ': 'O', 'Ỗ': 'O', 'Ộ': 'O',
        'Ơ': 'O', 'Ờ': 'O', 'Ớ': 'O', 'Ở': 'O', 'Ỡ': 'O', 'Ợ': 'O',
        'Ù': 'U', 'Ú': 'U', 'Ủ': 'U', 'Ũ': 'U', 'Ụ': 'U',
        'Ư': 'U', 'Ừ': 'U', 'Ứ': 'U', 'Ử': 'U', 'Ữ': 'U', 'Ự': 'U',
        'Ý': 'Y', 'Ỳ': 'Y', 'Ỷ': 'Y', 'Ỹ': 'Y', 'Ỵ': 'Y'
    }
    table = str.maketrans(mapping)
    return text.translate(table)


def clean_text_for_matching(text: str) -> str:
    """Chuẩn hóa văn bản trang web: bỏ dấu, viết thường, giữ khoảng cách để bảo toàn ranh giới từ."""
    if not text:
        return ""
    text = text.lower()
    text = remove_vietnamese_accents(text)
    # Thay thế các ký tự không phải chữ cái/chữ số bằng khoảng trắng
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    # Thu gọn khoảng trắng thừa thành 1 khoảng trắng duy nhất
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def domain_brand_tokens(brand: dict) -> set[str]:
    """Tạo token cho tên miền: Chuỗi liên tục không chứa khoảng trắng hoặc ký tự đặc biệt."""
    tokens = {brand.get("name", "")}
    tokens.update(brand.get("aliases", []) or [])
    for domain in brand.get("official_domains", []) or []:
        tokens.add(normalize_domain(domain).split(".")[0])
    cleaned = set()
    for token in tokens:
        token = remove_vietnamese_accents(token.lower())
        token = re.sub(r"[^a-z0-9]", "", token)
        if len(token) >= 3:
            cleaned.add(token)
    return cleaned


def text_brand_tokens(brand: dict) -> set[str]:
    """Tạo token cho nội dung web: Loại bỏ dấu nhưng giữ nguyên khoảng trắng để so khớp từ ghép."""
    tokens = {brand.get("name", "")}
    tokens.update(brand.get("aliases", []) or [])
    cleaned = set()
    for token in tokens:
        token = remove_vietnamese_accents(token.lower())
        token = re.sub(r"[^a-z0-9\s]", " ", token)
        token = re.sub(r"\s+", " ", token).strip()
        if len(token) >= 3:
            cleaned.add(token)
    return cleaned


class BrandMatcher:
    """Efficient brand matching using Aho-Corasick automaton with word boundaries."""
    def __init__(self, brands: list[dict]):
        self.brands = brands
        self.has_ac = False
        self.domain_token_to_brands = {}
        self.text_token_to_brands = {}
        
        for idx, brand in enumerate(brands):
            for token in domain_brand_tokens(brand):
                self.domain_token_to_brands.setdefault(token, []).append(idx)
            for token in text_brand_tokens(brand):
                self.text_token_to_brands.setdefault(token, []).append(idx)
                
        try:
            import ahocorasick
            
            # Automaton cho tên miền
            self.domain_automaton = ahocorasick.Automaton()
            for token in self.domain_token_to_brands:
                self.domain_automaton.add_word(token, token)
            self.domain_automaton.make_automaton()
            
            # Automaton cho nội dung text
            self.text_automaton = ahocorasick.Automaton()
            for token in self.text_token_to_brands:
                self.text_automaton.add_word(token, token)
            self.text_automaton.make_automaton()
            
            self.has_ac = True
        except ImportError:
            pass
            
    def match(self, domain: str, text: str) -> list[dict]:
        if not self.has_ac:
            return match_brands_fallback(domain, text, self.brands)
            
        clean_domain = re.sub(r"[^a-z0-9]", "", remove_vietnamese_accents(domain.lower()))
        clean_text = clean_text_for_matching(text)
        
        brand_evidences = {}
        
        # 1. So khớp tên miền (không cần kiểm tra ranh giới từ vì phishing hay chèn brand vào giữa domain)
        for end_index, token in self.domain_automaton.iter(clean_domain):
            for idx in self.domain_token_to_brands.get(token, []):
                brand_evidences.setdefault(idx, set()).add(f"domain contains brand token '{token}'")
                
        # 2. So khớp văn bản trang (bắt buộc kiểm tra ranh giới từ để tránh nhận diện sai)
        for end_index, token in self.text_automaton.iter(clean_text):
            start_index = end_index - len(token) + 1
            
            # Kiểm tra ký tự trước và sau từ khớp để xác định ranh giới từ (word boundary)
            is_left_boundary = (start_index == 0) or (not clean_text[start_index - 1].isalnum())
            is_right_boundary = (end_index == len(clean_text) - 1) or (not clean_text[end_index + 1].isalnum())
            
            if is_left_boundary and is_right_boundary:
                for idx in self.text_token_to_brands.get(token, []):
                    brand_evidences.setdefault(idx, set()).add(f"text contains brand token '{token}'")
                    
        matches = []
        for idx, evidences in brand_evidences.items():
            brand = self.brands[idx]
            matches.append({
                "brand": brand.get("name"),
                "sector": brand.get("sector"),
                "category": brand.get("category"),
                "evidence": sorted(list(evidences)),
            })
        return matches


def match_brands_fallback(domain: str, text: str, brands: list[dict]) -> list[dict]:
    """Fallback linear matching when pyahocorasick is not available."""
    clean_domain = re.sub(r"[^a-z0-9]", "", remove_vietnamese_accents(domain.lower()))
    clean_text = clean_text_for_matching(text)
    matches = []
    for brand in brands:
        evidence = []
        # So khớp domain
        for token in domain_brand_tokens(brand):
            if token in clean_domain:
                evidence.append(f"domain contains brand token '{token}'")
        # So khớp văn bản nội dung với ranh giới từ
        for token in text_brand_tokens(brand):
            start = 0
            while True:
                pos = clean_text.find(token, start)
                if pos == -1:
                    break
                end = pos + len(token) - 1
                is_left_boundary = (pos == 0) or (not clean_text[pos - 1].isalnum())
                is_right_boundary = (end == len(clean_text) - 1) or (not clean_text[end + 1].isalnum())
                
                if is_left_boundary and is_right_boundary:
                    evidence.append(f"text contains brand token '{token}'")
                    break
                start = pos + 1
                
        if evidence:
            matches.append({
                "brand": brand.get("name"),
                "sector": brand.get("sector"),
                "category": brand.get("category"),
                "evidence": sorted(list(set(evidence))),
            })
    return matches


def match_brands(domain: str, text: str, brands: list[dict]) -> list[dict]:
    """Backward compatible wrapper for match_brands."""
    matcher = BrandMatcher(brands)
    return matcher.match(domain, text)


def record_id_for(domain: str, label: int) -> str:
    digest = hashlib.sha1(f"{label}:{domain}".encode("utf-8")).hexdigest()[:12]
    prefix = "legit" if label == 0 else "phish" if label == 1 else "unknown"
    return f"{prefix}_{digest}"


def write_report(path: Path, title: str, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = [f"# {title}", "", f"Generated at: {utc_now()}", ""]
    body.extend(f"- {line}" for line in lines)
    body.append("")
    path.write_text("\n".join(body), encoding="utf-8")


def init_workspace(_: argparse.Namespace) -> dict:
    ensure_dirs()
    write_report(
        REPORT_DIR / "deploy_step1_workspace.md",
        "Workspace setup",
        [
            f"Project root: {PROJECT_DIR}",
            "Created/verified data/raw, data/html, data/screenshots, data/features, data/processed, reports, configs.",
            "Crawler policy: snapshot only; no form submission, no credential entry, no login bypass.",
        ],
    )
    write_report(
        REPORT_DIR / "deploy_step2_crawler_choice.md",
        "Crawler choice",
        [
            "Primary crawler: crawl_python/fetch_html.py followed by crawl_python/extract_text.py.",
            "Fallback crawlers: Firecrawl or Playwright are disabled by default and should be used only for snapshot evidence.",
            "Dataset/features consume only crawl_python/html/processed/*_text_*.jsonl.",
            "Short phishing pages are kept when form or password-field evidence exists.",
            "Crawler safety policy: no form submission, no credential entry, no login bypass, no OTP/password collection.",
        ],
    )
    return {"workspace": str(PROJECT_DIR)}


def check_domain_has_content(conn, domain: str) -> bool:
    """Check if the domain has extracted page content in SQLite."""
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM processed_pages WHERE domain = ? AND text IS NOT NULL AND text != ''", (domain,))
    return cursor.fetchone() is not None


def create_seed(args: argparse.Namespace) -> dict:
    brands = load_brands()
    matcher = BrandMatcher(brands)
    
    db_path = DATA_DIR / "dedup_cache.db"
    sync_processed_pages_to_db(db_path)
    
    import sqlite3
    conn = sqlite3.connect(db_path)
    
    blacklist = []
    seen = set()
    for value in read_lines(Path(args.blacklist)):
        domain = normalize_domain(value)
        if domain and domain not in seen:
            seen.add(domain)
            blacklist.append(domain)

    scored_blacklist = []
    for domain in blacklist:
        matches = matcher.match(domain, "")
        has_content = check_domain_has_content(conn, domain)
        if matches and has_content:
            score = 0
        elif matches:
            score = 1
        elif has_content:
            score = 2
        else:
            score = 3
        scored_blacklist.append((score, domain, matches, has_content))
    scored_blacklist.sort(key=lambda item: (item[0], item[1]))

    legit_domains = []
    if Path(args.whitelist).exists():
        legit_domains.extend(normalize_domain(v) for v in read_lines(Path(args.whitelist)))
    if len([d for d in legit_domains if d]) < args.legitimate_limit:
        for brand in brands:
            for official in brand.get("official_domains", []) or []:
                legit_domains.append(normalize_domain(official))

    dedup_legit = []
    seen_legit = set()
    for domain in legit_domains:
        if domain and domain not in seen_legit:
            seen_legit.add(domain)
            dedup_legit.append(domain)

    records = []
    for _, domain, matches, has_content in scored_blacklist[: args.phishing_limit]:
        evidence = ["listed in local eval_black_list.txt"]
        if has_content:
            evidence.append("local crawl has extracted text")
        evidence.extend(e for match in matches for e in match["evidence"])
        records.append({
            "record_id": record_id_for(domain, 1),
            "url": canonical_url(domain),
            "final_url": None,
            "domain": domain,
            "label": 1,
            "source": "local_blacklist",
            "source_ref": str(Path(args.blacklist)),
            "html_path": None,
            "screenshot_path": None,
            "observed_at": utc_now(),
            "evidence": sorted(set(evidence)),
        })

    for domain in dedup_legit[: args.legitimate_limit]:
        records.append({
            "record_id": record_id_for(domain, 0),
            "url": canonical_url(domain),
            "final_url": None,
            "domain": domain,
            "label": 0,
            "source": "brand_catalog_official_domains",
            "source_ref": str(BRAND_CATALOG),
            "html_path": None,
            "screenshot_path": None,
            "observed_at": utc_now(),
            "evidence": ["official domain from brand catalog"],
        })

    out_jsonl = RAW_DATA_DIR / "seed_dataset.jsonl"
    out_csv = RAW_DATA_DIR / "urls_seed.csv"
    with out_jsonl.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["record_id", "url", "domain", "label", "source"])
        writer.writeheader()
        for rec in records:
            writer.writerow({k: rec[k] for k in ["record_id", "url", "domain", "label", "source"]})

    stats = Counter(str(rec["label"]) for rec in records)
    write_report(
        REPORT_DIR / "deploy_step3_seed_dataset.md",
        "Seed dataset",
        [
            f"Records: {len(records)}",
            f"Phishing records: {stats.get('1', 0)}",
            f"Legitimate records: {stats.get('0', 0)}",
            f"Phishing records with local extracted text: {sum(1 for rec in records if rec['label'] == 1 and check_domain_has_content(conn, rec['domain']))}",
            f"Output JSONL: {out_jsonl}",
            f"Output CSV: {out_csv}",
        ],
    )
    conn.close()
    return {"records": len(records), "phishing": stats.get("1", 0), "legitimate": stats.get("0", 0)}


def sync_processed_pages_to_db(db_path: Path) -> None:
    """Synchronizes processed page details from JSONL files to SQLite processed_pages table.
    Uses synced_files table to skip files that haven't changed, making it extremely fast.
    """
    if not CRAWL_PROCESSED_DIR.exists():
        return
        
    db_path.parent.mkdir(parents=True, exist_ok=True)
    import sqlite3
    conn = sqlite3.connect(db_path)
    try:
        # Bật journal_mode WAL để tránh block ghi dữ liệu
        conn.execute("PRAGMA journal_mode=WAL;")
        cursor = conn.cursor()
        
        # Tạo bảng processed_pages lưu trữ thông tin có cấu trúc
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processed_pages (
                domain TEXT PRIMARY KEY,
                title TEXT,
                meta_description TEXT,
                forms_count INTEGER,
                has_password_field INTEGER,
                external_links TEXT,
                links_to_domains TEXT,
                method TEXT,
                fetched_at TEXT,
                source_file TEXT,
                text TEXT,
                screenshot_path TEXT
            )
        """)
        # Migration: ensure screenshot_path column exists
        try:
            cursor.execute("ALTER TABLE processed_pages ADD COLUMN screenshot_path TEXT")
        except sqlite3.OperationalError:
            pass
        
        # Kiểm tra tính sẵn sàng của FTS5
        fts5_available = True
        try:
            cursor.execute("CREATE VIRTUAL TABLE IF NOT EXISTS temp_fts USING fts5(val);")
            cursor.execute("DROP TABLE temp_fts;")
        except sqlite3.OperationalError:
            fts5_available = False
            
        if fts5_available:
            cursor.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS page_index USING fts5(
                    domain, 
                    content
                )
            """)
            
        # Tạo bảng tracking file đã đồng bộ để tối ưu hiệu năng chạy lại
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS synced_files (
                filepath TEXT PRIMARY KEY,
                file_size INTEGER,
                mtime REAL
            )
        """)
        conn.commit()
        
        # Đồng bộ hóa từng file JSONL
        for path in sorted(CRAWL_PROCESSED_DIR.glob("*.jsonl")):
            filepath_str = str(path.resolve())
            stat = path.stat()
            # Bỏ qua các file rỗng (0 bytes) do lỗi cào hoặc file rác
            if stat.st_size == 0:
                continue
                
            # Kiểm tra xem file đã từng được đồng bộ chưa và có thay đổi gì không
            cursor.execute("SELECT file_size, mtime FROM synced_files WHERE filepath = ?", (filepath_str,))
            row = cursor.fetchone()
            if row and row[0] == stat.st_size and row[1] == stat.st_mtime:
                # Không thay đổi gì, bỏ qua file này
                continue
                
            print(f"  [sync] Syncing processed file to SQLite: {path.name}")
            
            # Đọc và đồng bộ dữ liệu của file này
            records_to_insert = []
            fts_records_to_insert = []
            
            for rec in load_jsonl(path):
                domain = normalize_domain(rec.get("url") or rec.get("domain") or "")
                if not domain:
                    continue
                    
                ext_links = json.dumps(rec.get("external_links", []))
                link_doms = json.dumps(rec.get("links_to_domains", []))
                
                records_to_insert.append((
                    domain,
                    rec.get("title"),
                    rec.get("meta_description"),
                    rec.get("forms_count", 0),
                    1 if rec.get("has_password_field") else 0,
                    ext_links,
                    link_doms,
                    rec.get("method"),
                    rec.get("fetched_at"),
                    str(path.name),
                    rec.get("text", ""),
                    rec.get("screenshot_path")
                ))
                
                if fts5_available:
                    fts_records_to_insert.append((domain, rec.get("text", "")))
            
            # Chèn/ghi đè dữ liệu vào SQLite theo lô để tối ưu I/O
            if records_to_insert:
                cursor.executemany("""
                    INSERT OR REPLACE INTO processed_pages (
                        domain, title, meta_description, forms_count, has_password_field, 
                        external_links, links_to_domains, method, fetched_at, source_file, text, screenshot_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, records_to_insert)
                
                if fts5_available:
                    # Xóa FTS cũ của domain này trước khi ghi đè
                    domains_to_delete = [(r[0],) for r in fts_records_to_insert]
                    cursor.executemany("DELETE FROM page_index WHERE domain = ?", domains_to_delete)
                    cursor.executemany("INSERT INTO page_index (domain, content) VALUES (?, ?)", fts_records_to_insert)
                    
            # Ghi nhận trạng thái file đã đồng bộ
            cursor.execute("""
                INSERT OR REPLACE INTO synced_files (filepath, file_size, mtime) 
                VALUES (?, ?, ?)
            """, (filepath_str, stat.st_size, stat.st_mtime))
            conn.commit()
            
    finally:
        conn.close()


def get_processed_page_from_db(conn, domain: str) -> dict:
    """Retrieve processed page features from SQLite processed_pages table."""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT title, meta_description, forms_count, has_password_field, 
               external_links, links_to_domains, method, fetched_at, source_file, text, screenshot_path
        FROM processed_pages WHERE domain = ?
    """, (domain,))
    row = cursor.fetchone()
    if not row:
        return {}
    try:
        ext_links = json.loads(row[4]) if row[4] else []
    except Exception:
        ext_links = []
    try:
        link_doms = json.loads(row[5]) if row[5] else []
    except Exception:
        link_doms = []
        
    return {
        "title": row[0],
        "meta_description": row[1],
        "forms_count": row[2],
        "has_password_field": bool(row[3]),
        "external_links": ext_links,
        "links_to_domains": link_doms,
        "method": row[6],
        "fetched_at": row[7],
        "_source_file": row[8],
        "text": row[9],
        "screenshot_path": row[10]
    }


def processed_text_features(content: dict) -> dict:
    links_to_domains = content.get("links_to_domains") or []
    external_links = content.get("external_links") or []
    return {
        "title": content.get("title"),
        "meta_description": content.get("meta_description"),
        "forms_count": content.get("forms_count", 0),
        "has_password_field": bool(content.get("has_password_field")),
        "external_link_count": len(external_links),
        "links_to_domains": links_to_domains,
        "method": content.get("method"),
        "fetched_at": content.get("fetched_at"),
        "screenshot_path": content.get("screenshot_path"),
    }


def suspicious_tokens(domain: str, url: str) -> list[str]:
    text = f"{domain} {url}".lower()
    return sorted(token for token in SUSPICIOUS_TOKENS if token in text)


def extract_features(args: argparse.Namespace) -> dict:
    brands = load_brands()
    matcher = BrandMatcher(brands)
    records = load_jsonl(Path(args.seed))
    
    db_path = DATA_DIR / "dedup_cache.db"
    sync_processed_pages_to_db(db_path)
    
    import sqlite3
    conn = sqlite3.connect(db_path)

    out_path = FEATURE_DIR / "seed_features.jsonl"
    missing_text = 0
    with out_path.open("w", encoding="utf-8") as f:
        for rec in records:
            domain = rec["domain"]
            content = get_processed_page_from_db(conn, domain)
            text = content.get("text") or ""
            if not text:
                missing_text += 1
            features = {
                "record_id": rec["record_id"],
                "url": rec["url"],
                "domain": domain,
                "label": rec["label"],
                "source": rec["source"],
                "url_length": len(rec["url"]),
                "domain_length": len(domain),
                "subdomain_count": max(len(domain.split(".")) - 2, 0),
                "tld": domain.split(".")[-1] if "." in domain else "",
                "suspicious_tokens": suspicious_tokens(domain, rec["url"]),
                "brand_matches": matcher.match(domain, " ".join([text, content.get("title") or ""])),
                "text_length": len(text),
                "text": text,
                "content_source_file": content.get("_source_file"),
            }
            features.update(processed_text_features(content))
            f.write(json.dumps(features, ensure_ascii=False) + "\n")

    write_report(
        REPORT_DIR / "deploy_step4_features.md",
        "Feature extraction",
        [
            f"Input records: {len(records)}",
            f"Output: {out_path}",
            f"Records missing processed text evidence: {missing_text}",
            "URL/domain features are available for every seed record.",
            "Content features are read only from SQLite database backing processed pages.",
        ],
    )
    conn.close()
    return {"records": len(records), "missing_text": missing_text}


def run_all(args: argparse.Namespace) -> None:
    print("Initializing workspace...")
    init_res = init_workspace(args)
    print(f"Workspace Init: {json.dumps(init_res, ensure_ascii=False)}")
    
    print("\nCreating seed dataset...")
    seed_res = create_seed(args)
    print(f"Seed Dataset Creation Result: {json.dumps(seed_res, ensure_ascii=False)}")
    
    print("\nExtracting features from seed dataset...")
    feat_res = extract_features(argparse.Namespace(seed=str(RAW_DATA_DIR / "seed_dataset.jsonl")))
    print(f"Feature Extraction Result: {json.dumps(feat_res, ensure_ascii=False)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Vietnamese phishing dataset pipeline")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init")

    seed = sub.add_parser("seed")
    seed.add_argument("--blacklist", default=str(BLACK_FILE))
    seed.add_argument("--whitelist", default=str(WHITE_FILE))
    seed.add_argument("--phishing-limit", type=int, default=75)
    seed.add_argument("--legitimate-limit", type=int, default=75)

    features = sub.add_parser("features")
    features.add_argument("--seed", default=str(RAW_DATA_DIR / "seed_dataset.jsonl"))

    all_cmd = sub.add_parser("all")
    all_cmd.add_argument("--blacklist", default=str(BLACK_FILE))
    all_cmd.add_argument("--whitelist", default=str(WHITE_FILE))
    all_cmd.add_argument("--phishing-limit", type=int, default=75)
    all_cmd.add_argument("--legitimate-limit", type=int, default=75)

    args = parser.parse_args()
    ensure_dirs()

    if args.command == "init":
        print(json.dumps(init_workspace(args), ensure_ascii=False))
    elif args.command == "seed":
        print(json.dumps(create_seed(args), ensure_ascii=False))
    elif args.command == "features":
        print(json.dumps(extract_features(args), ensure_ascii=False))
    elif args.command == "all":
        run_all(args)
        print(json.dumps({"status": "ok", "project": str(PROJECT_DIR)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
