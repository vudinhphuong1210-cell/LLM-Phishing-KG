# Crawler URL lừa đảo / legit + LightRAG pipeline

Tool crawl URL từ **tinnhiemmang.vn** và **chongluadao.vn**,  
fetch HTML, extract text sạch → sẵn sàng cho **LightRAG**.

## Pipeline

```
┌─────────────────┐
│  crawl.py         │  Crawl URL từ tinnhiemmang + chongluadao
│  (domain lists)   │  → cập nhật data/eval_{black,white}_list.txt
└────────┬─────────┘
         │
┌────────▼─────────┐
│  fetch_html.py    │  Step 1: fetch HTML từ domain list
│                   │  - Multi-DNS (Google, Cloudflare, Quad9)
│                   │  - HTTP GET (https → http fallback)
│                   │  - Wayback Machine fallback
│                   │  - Tự động fix mojibake encoding
│                   │  → html/raw/{black,white}list_*.jsonl
└────────┬─────────┘
         │
┌────────▼─────────┐
│  extract_text.py  │  Step 2: extract text sạch từ raw HTML
│                   │  - BeautifulSoup parse
│                   │  - Strip script/style/nav/footer
│                   │  - Extract title, meta, visible text
│                   │  - Đếm form, password field, external links
│                   │  - Tự động fix mojibake encoding
│                   │  → html/processed/{black,white}list_text_*.jsonl
└────────┬─────────┘
         │
┌────────▼─────────┐
│  LightRAG         │  Step 3: insert text → knowledge graph
│                   │
│  lightrag.insert()│  → graph + vector index
│  lightrag.query() │  → classification / insight
└───────────────────┘
```

## Cài đặt

```bash
pip install -r requirements.txt
```

## Cách dùng

### Step 0: Crawl domain list (tuỳ chọn)

```bash
python crawl.py --source black     # cập nhật blacklist
python crawl.py --source white     # cập nhật whitelist
```

### Step 1: Fetch HTML

```bash
# Crawl cả black + white
python fetch_html.py

# Crawl 1 list, giới hạn 50 domain để test
python fetch_html.py --source black --limit 50

# Crawl cả 2 với 10 workers
python fetch_html.py --workers 10

# Fix mojibake trên file JSONL đã có (không fetch lại)
python fetch_html.py --fix-mojibake
```

Output: `html/raw/blacklist_20260529_153000.jsonl`

### Step 2: Extract text

```bash
# Xử lý file raw mới nhất (cả black + white)
python extract_text.py

# Xử lý file cụ thể
python extract_text.py --input html/raw/blacklist_20260529.jsonl

# Chỉ xử lý blacklist
python extract_text.py --source black

# Test 100 records
python extract_text.py --limit 100
```

Output: `html/processed/blacklist_text_20260529.jsonl`

## Xử lý lỗi encoding (mojibake)

### Vấn đề

Nhiều web VN trả `Content-Type: text/html; charset=iso-8859-1` hoặc
`windows-1252`, nhưng nội dung thực tế là **UTF-8**. Hậu quả:

```
Input:   "Má»¹ DuyÃªn"       ← mojibake
Output:  "Mỹ Duyên"          ← đã fix
```

### Cơ chế fix (tự động)

Cả `fetch_html.py` và `extract_text.py` đều có `fix_mojibake()`:

```python
def fix_mojibake(text):
    """
    - Đếm tỷ lệ ký tự Latin-1 Extended (0x80-0xFF)
    - Nếu >30% → encode lại bytes Latin-1, decode UTF-8
    
    Cơ chế: UTF-8 bytes bị đọc nhầm thành Latin-1
    → .encode("latin-1") phục hồi bytes gốc
    → .decode("utf-8")   cho text đúng
    """
```

### Fix thủ công cho file đã có

```bash
python fetch_html.py --fix-mojibake
```

Lệnh này quét toàn bộ file trong `html/raw/`, fix mojibake và ghi đè.

## JSONL format

### Raw (Step 1)

```json
{
  "url": "example.com",
  "source": "black",
  "html": "<!DOCTYPE html>...",
  "fetched_at": "2026-05-29T15:30:00",
  "method": "direct",
  "status_code": 200,
  "error": null
}
```

### Processed (Step 2)

```json
{
  "url": "example.com",
  "source": "black",
  "title": "Trang chủ",
  "meta_description": "...",
  "text": "Nội dung text sạch...",
  "text_length": 1234,
  "forms_count": 2,
  "has_password_field": true,
  "external_links": ["https://other.com/login"],
  "links_to_domains": ["other.com"],
  "method": "direct",
  "fetched_at": "2026-05-29T15:30:00"
}
```

## Cấu trúc thư mục

```
crawl_python/
├── crawl.py                    # Step 0: crawl domain từ web
├── fetch_html.py               # Step 1: fetch HTML
├── extract_text.py             # Step 2: extract text
├── requirements.txt
├── README.md
└── html/
    ├── fetch.log
    ├── extract.log
    ├── raw/                    # Step 1 output
    │   ├── blacklist_*.jsonl
    │   └── whitelist_*.jsonl
    └── processed/              # Step 2 output
        ├── blacklist_text_*.jsonl
        └── whitelist_text_*.jsonl
```
