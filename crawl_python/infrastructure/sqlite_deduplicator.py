import sqlite3
import os
import threading
import hashlib
from datetime import datetime
from typing import List, Set
from core.interfaces import IDeduplicator

class SqliteDeduplicator(IDeduplicator):
    """
    Cài đặt IDeduplicator sử dụng SQLite làm nơi lưu trữ trung tâm.
    - Hỗ trợ thao tác đồng thời (thread-safe) với WAL mode.
    - Dùng mã băm (MD5) để làm khóa chính giúp tối ưu B-Tree.
    - Hỗ trợ xử lý theo lô (batching) để tăng tốc I/O.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.lock = threading.Lock()
        self._init_db()

    def _get_hash(self, url: str) -> str:
        # Băm URL để tối ưu Index và dung lượng DB
        return hashlib.md5(url.encode('utf-8')).hexdigest()

    def _init_db(self):
        with self.lock:
            # Dùng timeout=30.0 để tránh lỗi Database is locked khi đồng thời truy cập
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                # Bật chế độ WAL giúp tránh lỗi Database is locked khi có Concurrent Read/Write
                conn.execute('PRAGMA journal_mode=WAL;')
                cursor = conn.cursor()
                
                try:
                    # Bắt đầu giao dịch Exclusive để bảo vệ quá trình kiểm tra và nâng cấp schema (nếu có)
                    conn.execute("BEGIN EXCLUSIVE")
                    
                    # Kiểm tra xem table seen_urls đã tồn tại và dùng PK cũ (chỉ url_hash) không
                    cursor.execute("PRAGMA table_info(seen_urls)")
                    columns = cursor.fetchall()
                    if columns:
                        pk_count = sum(1 for col in columns if col[5] > 0)
                        if pk_count == 1:
                            # Schema cũ có duy nhất url_hash làm PK -> Drop để migrate sang PK kép
                            cursor.execute("DROP TABLE seen_urls")
                    
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS seen_urls (
                            url_hash VARCHAR(32),
                            url TEXT,
                            list_type VARCHAR(20),
                            created_at DATETIME,
                            PRIMARY KEY (url_hash, list_type)
                        )
                    """)
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_list_type ON seen_urls(list_type);")
                    conn.commit()
                except sqlite3.OperationalError:
                    # Nếu database đang bị khóa bởi tiến trình khác (có thể đang chạy Migration),
                    # rollback giao dịch và để tiến trình khác hoàn thành.
                    conn.rollback()
                    # Khi lock được giải phóng, cấu trúc bảng đã được tiến trình kia đảm bảo.
                    # Ta vẫn thử tạo bảng ngoài Exclusive block đề phòng trường hợp bảng chưa tồn tại.
                    with sqlite3.connect(self.db_path, timeout=30.0) as conn2:
                        conn2.execute('PRAGMA journal_mode=WAL;')
                        cursor2 = conn2.cursor()
                        cursor2.execute("""
                            CREATE TABLE IF NOT EXISTS seen_urls (
                                url_hash VARCHAR(32),
                                url TEXT,
                                list_type VARCHAR(20),
                                created_at DATETIME,
                                PRIMARY KEY (url_hash, list_type)
                            )
                        """)
                        cursor2.execute("CREATE INDEX IF NOT EXISTS idx_list_type ON seen_urls(list_type);")
                        conn2.commit()

    def is_duplicate(self, url: str, list_type: str = 'raw') -> bool:
        url_hash = self._get_hash(url)
        with self.lock:
            try:
                with sqlite3.connect(self.db_path, timeout=15.0) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO seen_urls (url_hash, url, list_type, created_at) VALUES (?, ?, ?, ?)", 
                        (url_hash, url, list_type, datetime.now())
                    )
                    conn.commit()
                    return False
            except sqlite3.IntegrityError:
                return True

    def is_in_whitelist(self, url: str) -> bool:
        url_hash = self._get_hash(url)
        with sqlite3.connect(self.db_path, timeout=15.0) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM seen_urls WHERE url_hash = ? AND list_type = 'whitelist'", (url_hash,))
            return cursor.fetchone() is not None

    def filter_and_add_batch(self, urls: List[str], list_type: str = 'raw', read_only: bool = False) -> List[str]:
        if not urls:
            return []
            
        new_urls = []
        with self.lock:
            with sqlite3.connect(self.db_path, timeout=15.0) as conn:
                cursor = conn.cursor()
                
                # 1. Băm URL và tra cứu theo lô, lọc theo list_type cụ thể
                hashes = {self._get_hash(u): u for u in urls}
                placeholders = ','.join(['?'] * len(hashes))
                
                cursor.execute(
                    f"SELECT url_hash FROM seen_urls WHERE url_hash IN ({placeholders}) AND list_type = ?", 
                    list(hashes.keys()) + [list_type]
                )
                existing_hashes = {row[0] for row in cursor.fetchall()}
                
                # 2. Lọc ra những URL thực sự mới
                batch_data = []
                now = datetime.now()
                for h, u in hashes.items():
                    if h not in existing_hashes:
                        new_urls.append(u)
                        batch_data.append((h, u, list_type, now))
                
                # 3. Ghi vào DB bằng 1 transaction duy nhất (executemany) nếu không phải read_only
                if batch_data and not read_only:
                    cursor.executemany(
                        "INSERT OR IGNORE INTO seen_urls (url_hash, url, list_type, created_at) VALUES (?, ?, ?, ?)", 
                        batch_data
                    )
                conn.commit()
                
        return new_urls

    def get_existing_in_list(self, urls: List[str], list_type: str) -> Set[str]:
        if not urls:
            return set()
            
        with self.lock:
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                cursor = conn.cursor()
                hashes = {self._get_hash(u): u for u in urls}
                placeholders = ','.join(['?'] * len(hashes))
                cursor.execute(
                    f"SELECT url_hash FROM seen_urls WHERE url_hash IN ({placeholders}) AND list_type = ?",
                    list(hashes.keys()) + [list_type]
                )
                existing_hashes = {row[0] for row in cursor.fetchall()}
                return {hashes[h] for h in existing_hashes if h in hashes}
