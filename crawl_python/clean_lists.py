#!/usr/bin/env python3
"""
Script lọc và làm sạch file eval_black_list.txt và eval_white_list.txt:
- Loại bỏ các dòng lỗi định dạng (thẻ HTML, ký tự đặc biệt).
- Xóa tiền tố wildcard (*. hoặc .).
- Xóa cổng (port) hoặc dấu hai chấm thừa ở cuối.
- Loại bỏ trùng lặp và sắp xếp lại A-Z.
- Với Blacklist: Loại bỏ thêm các tên miền gốc của nền tảng lớn (tránh ô nhiễm dữ liệu).
- Với Whitelist: Giữ lại các tên miền gốc sạch (ví dụ: google.com, github.com).
"""

import os
import re
import shutil
import sys
import argparse

# Fix console encoding for Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
DATA_DIR = os.path.join(PROJECT_DIR, "data")

BLACK_FILE = os.path.join(DATA_DIR, "eval_black_list.txt")
WHITE_FILE = os.path.join(DATA_DIR, "eval_white_list.txt")

# Tên miền nền tảng lớn (chỉ loại bỏ khỏi blacklist)
PLATFORM_ROOTS = {
    "blogspot.com", "weebly.com", "wixsite.com", "github.io", "vercel.app", 
    "firebaseapp.com", "pages.dev", "pantheonsite.io", "000webhostapp.com", 
    "azurewebsites.net", "appdomain.cloud", "appspot.com", "freecluster.eu",
    "byethost18.com", "byethost31.com", "amazonaws.com", "github.com", 
    "google.com", "facebook.com", "zalo.me", "telegram.org", 
    "drive.google.com", "docs.google.com"
}

# Từ khóa/Regex nhận diện các trang cờ bạc, cá độ, game bài, khiêu dâm, mại dâm (để loại bỏ khỏi blacklist)
GAMBLING_ADULT_PATTERNS = [
    # General gambling/betting terms
    r'bet\d*', r'\d+bet', r'casino', r'daga', r'dagasv', r'gamebai', r'nohu',
    r'lode', r'xoso', r'taixiu', r'chanle', r'cacuoc', r'soica', r'bongda',
    r'quayhu', r'no-hu', r'tai-xiu', r'chan-le', r'ca-cuoc', r'game-bai',
    r'xocdia', r'xoc-dia', r'da-ga',
    
    # Specific major gambling platforms/brands in Vietnam
    r'jun88', r'hi88', r'shbet', r'fabet', r'fi88', r'w88', r'm88', r'fun88', 
    r'fb88', r'sv388', r'bong88', r'v9bet', r'go88', r'sunwin', r'rikvip', 
    r'iwin', r'kubet', r'thabet', r'cwin', r'789win', r'8kbet', r'ok365', 
    r'789bet', r'k8bet', r'new88', r'mu88', r'lixi88', r'vnloto', r'loto188', 
    r'cakhiatv', r'cakhia', r'ae888', r'az888', r'alo789', r'choangclub',
    r'ezb68', r'lvs788', r'happyluke', r'dabet', r'sin88', r'may88', r'yo88',
    r'b52', r'fa88', r'kingfun', r'zoocasino',
    
    # Club/Clb variations
    r'clb789', r'club789', r'789club',
    
    # Common chẵn lẻ MoMo/Zalo variations
    r'cltx', r'chanlemomo', r'chanlebank', r'clzalo', r'clzl',
    
    # Number + win/bet patterns (avoiding winmart, twin, windows)
    r'\d+win', r'win\d+', r'winvn', r'88online', r'88onlines', r'88online\d+',
    r'win88', r'88win', r'win888', r'888win', r'8877999', r'90988pk',
    r'9527828', r'32457\.cc', r'398c\.live', r'4488new', r'555wing',
    r'558-558-559', r'577768', r'66a86', r'66twmevn', r'7866club',
    r'85\.192\.61\.65', r'900ooo', r'123bii',
    
    # Adult/Prostitution keywords
    r'sex', r'porn', r'gaigoi', r'gai-goi', r'gaishow', r'hentai', r'clipnong',
    r'phimnong', r'jav', r'pussy', r'adult', r'mại-dâm', r'maidam'
]

def clean_domain(domain: str, is_blacklist: bool = True) -> str | None:
    # 1. Chuyển về chữ thường, xóa khoảng trắng thừa ở hai đầu
    domain = domain.strip().lower()
    
    # 2. Bỏ qua các dòng chứa thẻ HTML/SVG hoặc rỗng
    if not domain or "<" in domain or ">" in domain or "xmlns=" in domain or "fill=" in domain:
        return None
        
    # 3. Loại bỏ protocol nếu lỡ có trong danh sách
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]
        
    # 4. Loại bỏ các tiền tố wildcard (*. hoặc .)
    if domain.startswith("*."):
        domain = domain[2:]
    if domain.startswith("."):
        domain = domain[1:]
        
    # 5. Loại bỏ path nếu có (ví dụ: domain.com/path -> domain.com)
    domain = domain.split("/")[0]
    
    # 6. Loại bỏ cổng (port) thừa ở cuối (ví dụ: 198.252.110.115:5740 -> 198.252.110.115)
    # hoặc loại bỏ dấu hai chấm thừa ở cuối
    if ":" in domain:
        domain = domain.split(":")[0]
        
    domain = domain.strip()
    
    # 7. Phải có ít nhất một dấu chấm (domain hoặc IP hợp lệ)
    if "." not in domain:
        return None
        
    # 8. Chỉ loại bỏ tên miền gốc của nền tảng lớn nếu là BLACKLIST
    if is_blacklist and domain in PLATFORM_ROOTS:
        return None
        
    # 9. Loại bỏ các trang cờ bạc, mại dâm nếu là BLACKLIST
    if is_blacklist:
        for pat in GAMBLING_ADULT_PATTERNS:
            if re.search(pat, domain):
                # Loại bỏ false positive (ví dụ: chữ "sex" nằm trong "express" + "extra" như jtexpressextra.com)
                if "express" in domain and "sex" in domain and not any(kw in domain for kw in ["porn", "gaigoi", "jav"]):
                    continue
                return None
        
    # 10. Chỉ cho phép ký tự chữ, số, dấu gạch ngang và dấu chấm
    if not re.match(r'^[a-z0-9\-.]+$', domain):
        return None
        
    return domain

def clean_file(filepath: str, is_blacklist: bool):
    if not os.path.exists(filepath):
        print(f"Bỏ qua: File không tồn tại tại {filepath}")
        return
        
    backup_path = filepath + ".bak"
    shutil.copy2(filepath, backup_path)
    print(f"Đã tạo bản backup tại: {backup_path}")
    
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    original_count = len(lines)
    cleaned_domains = set()
    ignored_count = 0
    
    for line in lines:
        cleaned = clean_domain(line, is_blacklist)
        if cleaned:
            cleaned_domains.add(cleaned)
        else:
            ignored_count += 1
            
    sorted_domains = sorted(list(cleaned_domains))
    
    with open(filepath, "w", encoding="utf-8") as f:
        for d in sorted_domains:
            f.write(d + "\n")
            
    label = "DANH SÁCH ĐEN (BLACKLIST)" if is_blacklist else "DANH SÁCH TRẮNG (WHITELIST)"
    print(f"\n=== KẾT QUẢ LỌC {label} ===")
    print(f"Số lượng domain ban đầu   : {original_count}")
    print(f"Số lượng bị loại bỏ (lỗi) : {ignored_count}")
    print(f"Số lượng trùng lặp bị gộp : {original_count - ignored_count - len(sorted_domains)}")
    print(f"Số lượng domain sạch còn lại: {len(sorted_domains)}")
    print(f"Đã cập nhật đè lên file   : {filepath}\n")

def main():
    parser = argparse.ArgumentParser(description="Lọc và làm sạch blacklist/whitelist")
    parser.add_argument(
        "--source", "-s",
        choices=["black", "white", "both"],
        default="both",
        help="Nguồn cần lọc (black, white, hoặc cả hai - mặc định: both)"
    )
    args = parser.parse_args()
    
    if args.source in ("black", "both"):
        clean_file(BLACK_FILE, is_blacklist=True)
    if args.source in ("white", "both"):
        clean_file(WHITE_FILE, is_blacklist=False)

if __name__ == "__main__":
    main()
