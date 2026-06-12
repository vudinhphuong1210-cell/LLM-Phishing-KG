# Crawler URL phishing/scam Viet Nam

Scope hien tai cua thu muc nay:

1. Crawl URL/domain Viet Nam.
2. Fetch HTML snapshot tam thoi.
3. Extract clean text tu HTML.
4. Tao seed dataset va feature dataset.

## Cai dat

```bash
pip install -r requirements.txt
```

## Quy trình thực hiện Pipeline (Từng bước chi tiết)

Dưới đây là các bước chạy chi tiết của hệ thống từ lúc thu thập URL gốc cho đến khi trích xuất ra tập dữ liệu đặc trưng (Features) hoàn chỉnh.

---

### Bước 0 - Thu thập URL/Tên miền gốc (Seeds Collection)

Bước này thực hiện crawl danh sách các tên miền lừa đảo (blacklist) và tên miền tin cậy (whitelist) từ các nguồn mở tại Việt Nam và quốc tế.

*   **Cú pháp chạy:**
    ```bash
    # Thu thập blacklist Việt Nam (Tin Nhiệm Mạng + Chống Lừa Đảo), giới hạn 20 trang để kiểm tra
    python crawl.py --source black --max-pages 20

    # Thu thập whitelist Việt Nam (Tin Nhiệm Mạng + Chống Lừa Đảo)
    python crawl.py --source white --max-pages 10

    # Thu thập nguồn phụ trợ quốc tế (nếu cần dữ liệu nghiên cứu thêm, chạy dry-run test)
    python collect_sources.py --sources openphish,phishtank --per-source-limit 1000 --dry-run
    ```
*   **Đầu ra (Outputs):**
    *   `data/eval_black_list.txt` (Danh sách đen thô)
    *   `data/eval_white_list.txt` (Danh sách trắng thô)

---

### Bước 0.5 - Làm sạch danh sách URL & Lọc cờ bạc, mại dâm (URL Domain Cleaning)

Bước này chuẩn hóa định dạng tên miền và tự động loại bỏ các tên miền cờ bạc, cá độ, game bài, khiêu dâm, mại dâm ra khỏi danh sách blacklist trước khi đem đi crawl.

*   **Cú pháp chạy:**
    ```bash
    # Làm sạch cả Blacklist và Whitelist, loại bỏ cờ bạc, mại dâm khỏi Blacklist
    python clean_lists.py --source both

    # Hoặc chỉ chạy làm sạch riêng Blacklist
    python clean_lists.py --source black
    ```
*   **Đầu vào (Inputs):**
    *   `data/eval_black_list.txt`
    *   `data/eval_white_list.txt`
*   **Đầu ra (Outputs):**
    *   Cập nhật trực tiếp đè lên file `data/eval_black_list.txt` và `data/eval_white_list.txt`.
    *   Tự động sao lưu file gốc chưa lọc sang dạng `.bak` (ví dụ: `eval_black_list.txt.bak`).

---

### Bước 1 - Tải nội dung HTML tĩnh (Fetch HTML)

Thực hiện gửi request tải nội dung HTML từ danh sách tên miền đã được lọc ở trên, hỗ trợ cơ chế tải lưu trữ dự phòng (Wayback Machine) nếu trang web hiện tại đã chết.

*   **Cú pháp chạy:**
    ```bash
    # Tải HTML của Blacklist, giới hạn 100 trang để test, chạy 10 luồng song song, lọc trang dưới 50 từ
    python fetch_html.py --source black --limit 100 --workers 10 --min-words 50

    # Tải HTML của Whitelist
    python fetch_html.py --source white --limit 100 --workers 10 --min-words 50
    ```
*   **Đầu vào (Inputs):**
    *   `data/eval_black_list.txt` hoặc `data/eval_white_list.txt`
*   **Đầu ra (Outputs):**
    *   `crawl_python/html/raw/blacklist_YYYYMMDD_HHMMSS.jsonl` (chứa mã nguồn HTML thô)
    *   `crawl_python/html/raw/whitelist_YYYYMMDD_HHMMSS.jsonl`

---

### Bước 2 - Làm sạch nội dung HTML thô (HTML Records Cleaning)

Bộ lọc nội dung HTML giúp loại bỏ các bản ghi tải lỗi (HTML null), trang trùng lặp, các trang thông báo lỗi (404, 403), trang đỗ tên miền (parking page), hoặc các trang quá ngắn không chứa form nhập liệu.

*   **Cú pháp chạy:**
    ```bash
    # Lọc file thô của Blacklist vừa crawl (mặc định lọc các trang dưới 200 từ)
    python clean_blacklist.py --source black --min-words 200

    # Hoặc chạy chỉ định một file cụ thể
    python clean_blacklist.py -i html/raw/blacklist_20260612_010438.jsonl --min-words 200
    ```
*   **Đầu vào (Inputs):**
    *   `crawl_python/html/raw/*.jsonl`
*   **Đầu ra (Outputs):**
    *   `crawl_python/html/raw/*_cleaned.jsonl`

---

### Bước 3 - Trích xuất thông tin & Nội dung văn bản (Text Extraction)

Đọc file HTML đã làm sạch, loại bỏ các thẻ gây nhiễu (style, script, footer, nav) và trích xuất ra cấu trúc thông tin sạch (tiêu đề, thẻ meta, text hiển thị, form nhập liệu, đường dẫn ngoài).

*   **Cú pháp chạy:**
    ```bash
    # Trích xuất dữ liệu từ các file blacklist đã clean
    python extract_text.py --source black

    # Trích xuất cho cả whitelist và blacklist
    python extract_text.py --source both
    ```
*   **Đầu vào (Inputs):**
    *   `crawl_python/html/raw/*_cleaned.jsonl`
*   **Đầu ra (Outputs):**
    *   `crawl_python/html/processed/blacklist_text_YYYYMMDD_HHMMSS.jsonl`
    *   `crawl_python/html/processed/whitelist_text_YYYYMMDD_HHMMSS.jsonl`

*Lưu ý:* Sau khi hoàn tất bước này, anh có thể xóa các file raw HTML nặng để tiết kiệm dung lượng đĩa bằng lệnh:
```bash
powershell -Command "Remove-Item .\html\raw\*.jsonl -Force"
```

---

### Bước 4 - Tạo Seed Dataset & Trích xuất Đặc trưng (Features Dataset)

Tích hợp thông tin văn bản đã trích xuất, đối chiếu với danh mục thương hiệu chính thống ([brand_catalog.json](file:///d:/phishing/llm-phishing-KG/crawl_python/brand_catalog.json)) để tạo ra tập dữ liệu đặc trưng (seed dataset + features) phục vụ huấn luyện mô hình học máy và xây dựng đồ thị tri thức (Knowledge Graph).

*   **Cú pháp chạy từng lệnh nhỏ:**
    ```bash
    # 1. Khởi tạo cấu trúc thư mục dữ liệu
    python phishing_mvp_pipeline.py init

    # 2. Tạo tập seed dataset (lấy 75 phish, 75 legit)
    python phishing_mvp_pipeline.py seed --phishing-limit 75 --legitimate-limit 75

    # 3. Trích xuất đặc trưng (Features) từ tập seed
    python phishing_mvp_pipeline.py features
    ```
*   **Hoặc chạy toàn bộ bước 4 bằng 1 lệnh duy nhất:**
    ```bash
    python phishing_mvp_pipeline.py all --phishing-limit 75 --legitimate-limit 75
    ```
*   **Đầu vào (Inputs):**
    *   `crawl_python/html/processed/*_text_*.jsonl`
    *   `crawl_python/brand_catalog.json`
*   **Đầu ra (Outputs):**
    *   `data/raw/seed_dataset.jsonl` (Tập seed dataset)
    *   `data/raw/urls_seed.csv` (File CSV tương ứng)
    *   `data/features/seed_features.jsonl` (Tập đặc trưng đầy đủ của các URL)
    *   `reports/deploy_step1_workspace.md` đến `deploy_step4_features.md` (Báo cáo quy trình)

---

## Nguyên tắc An toàn (Safety & Policies)

Quy trình crawler được thiết kế theo nguyên tắc an toàn, không tương tác độc hại:
*   Chỉ chụp ảnh thông tin tĩnh (Snapshot), không tự động điền form (no form submission).
*   Không nhập tài khoản, mật khẩu (no credential entry).
*   Không thu thập mã OTP hoặc thông tin nhạy cảm của người dùng.
*   Không tự động vượt qua các cơ chế đăng nhập (no login bypass).
*   Không kích hoạt hoặc tải về các phần mềm độc hại (malware payload).
