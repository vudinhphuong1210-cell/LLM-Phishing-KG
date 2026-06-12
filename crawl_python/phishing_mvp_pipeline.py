#!/usr/bin/env python3
"""Offline-first dataset pipeline for Vietnamese phishing URL research."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
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


def brand_tokens(brand: dict) -> set[str]:
    tokens = {brand.get("name", "")}
    tokens.update(brand.get("aliases", []) or [])
    for domain in brand.get("official_domains", []) or []:
        tokens.add(normalize_domain(domain).split(".")[0])
    cleaned = set()
    for token in tokens:
        token = re.sub(r"[^a-z0-9]", "", token.lower())
        if len(token) >= 3:
            cleaned.add(token)
    return cleaned


def match_brands(domain: str, text: str, brands: list[dict]) -> list[dict]:
    domain_text = re.sub(r"[^a-z0-9]", "", domain.lower())
    page_text = re.sub(r"[^a-z0-9]", "", (text or "").lower())
    matches = []
    for brand in brands:
        evidence = []
        for token in brand_tokens(brand):
            if token in domain_text:
                evidence.append(f"domain contains brand token '{token}'")
            elif token in page_text:
                evidence.append(f"text contains brand token '{token}'")
        if evidence:
            matches.append({
                "brand": brand.get("name"),
                "sector": brand.get("sector"),
                "category": brand.get("category"),
                "evidence": sorted(set(evidence)),
            })
    return matches


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


def create_seed(args: argparse.Namespace) -> dict:
    brands = load_brands()
    content_index = build_content_index()
    blacklist = []
    seen = set()
    for value in read_lines(Path(args.blacklist)):
        domain = normalize_domain(value)
        if domain and domain not in seen:
            seen.add(domain)
            blacklist.append(domain)

    scored_blacklist = []
    for domain in blacklist:
        matches = match_brands(domain, "", brands)
        has_content = domain in content_index
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
            f"Phishing records with local extracted text: {sum(1 for rec in records if rec['label'] == 1 and rec['domain'] in content_index)}",
            f"Output JSONL: {out_jsonl}",
            f"Output CSV: {out_csv}",
        ],
    )
    return {"records": len(records), "phishing": stats.get("1", 0), "legitimate": stats.get("0", 0)}


def build_content_index() -> dict[str, dict]:
    index = {}
    if not CRAWL_PROCESSED_DIR.exists():
        return index
    for path in sorted(CRAWL_PROCESSED_DIR.glob("*.jsonl")):
        for rec in load_jsonl(path):
            domain = normalize_domain(rec.get("url") or rec.get("domain") or "")
            if domain and domain not in index and rec.get("text"):
                copied = dict(rec)
                copied["_source_file"] = str(path)
                index[domain] = copied
    return index


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
    }


def suspicious_tokens(domain: str, url: str) -> list[str]:
    text = f"{domain} {url}".lower()
    return sorted(token for token in SUSPICIOUS_TOKENS if token in text)


def extract_features(args: argparse.Namespace) -> dict:
    brands = load_brands()
    records = load_jsonl(Path(args.seed))
    content_index = build_content_index()

    out_path = FEATURE_DIR / "seed_features.jsonl"
    missing_text = 0
    with out_path.open("w", encoding="utf-8") as f:
        for rec in records:
            domain = rec["domain"]
            content = content_index.get(domain, {})
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
                "brand_matches": match_brands(domain, " ".join([text, content.get("title") or ""]), brands),
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
            "Content features are read only from crawl_python/html/processed/*_text_*.jsonl.",
        ],
    )
    return {"records": len(records), "missing_text": missing_text}


def run_all(args: argparse.Namespace) -> None:
    init_workspace(args)
    create_seed(args)
    extract_features(argparse.Namespace(seed=str(RAW_DATA_DIR / "seed_dataset.jsonl")))


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
