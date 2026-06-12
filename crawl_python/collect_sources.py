#!/usr/bin/env python3
"""Collect phishing and legitimate URL/domain seeds from public feeds.

This script only downloads public feed files and normalizes URL/domain seeds.
It does not fetch target website HTML, click links, submit forms, or interact
with phishing pages.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import re
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
DATA_DIR = PROJECT_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
BLACK_FILE = DATA_DIR / "eval_black_list.txt"
WHITE_FILE = DATA_DIR / "eval_white_list.txt"

HEADERS = {
    "User-Agent": "llm-phishing-KG-research/1.0 contact:local-research"
}
TIMEOUT = 60

SOURCES = {
    "openphish": {
        "label": 1,
        "kind": "url_list",
        "url": "https://openphish.com/feed.txt",
        "description": "OpenPhish public phishing URL feed",
    },
    "phishtank": {
        "label": 1,
        "kind": "phishtank_csv",
        "url": "https://data.phishtank.com/data/online-valid.csv",
        "fallback_url": "http://data.phishtank.com/data/online-valid.csv",
        "description": "PhishTank online-valid verified phishing CSV",
    },
    "phishing_database_domains": {
        "label": 1,
        "kind": "domain_list",
        "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "description": "Phishing.Database active phishing domains",
    },
    "phishing_database_links": {
        "label": 1,
        "kind": "url_list",
        "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
        "description": "Phishing.Database active phishing links",
    },
    "tranco_top": {
        "label": 0,
        "kind": "tranco_zip",
        "url": "https://tranco-list.eu/top-1m.csv.zip",
        "description": "Tranco latest top domains for legitimate baseline",
    },
    "urlhaus_malware": {
        "label": -1,
        "kind": "url_list",
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "description": "URLhaus malware URL feed, not phishing; use only as malicious-URL auxiliary data",
    },
}

DEFAULT_SOURCES = [
    "openphish",
    "phishtank",
    "phishing_database_domains",
    "phishing_database_links",
    "tranco_top",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
    if not host or "." not in host:
        return ""
    if not re.match(r"^[a-z0-9.-]+$", host):
        return ""
    return host


def normalize_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    return value if "://" in value else "http://" + value


def read_domain_file(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with path.open("r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


def write_domain_file(path: Path, domains: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for domain in sorted(domains):
            f.write(domain + "\n")


def fetch_bytes(source: dict) -> tuple[bytes, str]:
    urls = [source["url"]]
    if source.get("fallback_url"):
        urls.append(source["fallback_url"])
    last_error = None
    for url in urls:
        try:
            response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            response.raise_for_status()
            return response.content, response.url
        except requests.RequestException as exc:
            last_error = exc
            time.sleep(1)
    raise RuntimeError(f"failed to fetch {source['description']}: {last_error}")


def decode_payload(payload: bytes, url: str) -> str:
    if url.endswith(".gz"):
        payload = gzip.decompress(payload)
    return payload.decode("utf-8", errors="replace")


def parse_plain_lines(text: str, source_name: str, label: int, is_domain_only: bool) -> list[dict]:
    records = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith(("#", "!", "//")):
            continue
        if "," in value and not value.startswith(("http://", "https://")):
            value = value.split(",")[-1].strip()
        domain = normalize_domain(value)
        if not domain:
            continue
        records.append({
            "source": source_name,
            "label": label,
            "url": normalize_url(domain if is_domain_only else value),
            "domain": domain,
            "raw_value": value,
            "line_no": line_no,
            "collected_at": utc_now(),
        })
    return records


def parse_phishtank_csv(text: str, source_name: str, label: int) -> list[dict]:
    records = []
    reader = csv.DictReader(io.StringIO(text))
    for line_no, row in enumerate(reader, 2):
        value = row.get("url") or ""
        domain = normalize_domain(value)
        if not domain:
            continue
        records.append({
            "source": source_name,
            "label": label,
            "url": value.strip(),
            "domain": domain,
            "raw_value": value.strip(),
            "line_no": line_no,
            "phish_id": row.get("phish_id"),
            "target": row.get("target"),
            "submission_time": row.get("submission_time"),
            "verification_time": row.get("verification_time"),
            "collected_at": utc_now(),
        })
    return records


def parse_tranco_zip(payload: bytes, source_name: str, label: int, limit: int | None) -> list[dict]:
    records = []
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        csv_name = next((name for name in zf.namelist() if name.endswith(".csv")), None)
        if not csv_name:
            return records
        with zf.open(csv_name) as f:
            text = f.read().decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text))
    for line_no, row in enumerate(reader, 1):
        if len(row) < 2:
            continue
        rank, domain = row[0].strip(), normalize_domain(row[1])
        if not domain:
            continue
        records.append({
            "source": source_name,
            "label": label,
            "url": "http://" + domain,
            "domain": domain,
            "raw_value": ",".join(row),
            "line_no": line_no,
            "rank": int(rank) if rank.isdigit() else None,
            "collected_at": utc_now(),
        })
        if limit and len(records) >= limit:
            break
    return records


def collect_one(source_name: str, per_source_limit: int | None) -> list[dict]:
    source = SOURCES[source_name]
    payload, final_url = fetch_bytes(source)
    kind = source["kind"]
    if kind == "tranco_zip":
        records = parse_tranco_zip(payload, source_name, source["label"], per_source_limit)
    else:
        text = decode_payload(payload, final_url)
        if kind == "phishtank_csv":
            records = parse_phishtank_csv(text, source_name, source["label"])
        elif kind == "domain_list":
            records = parse_plain_lines(text, source_name, source["label"], is_domain_only=True)
        elif kind == "url_list":
            records = parse_plain_lines(text, source_name, source["label"], is_domain_only=False)
        else:
            raise ValueError(f"unsupported source kind: {kind}")
        if per_source_limit:
            records = records[:per_source_limit]
    return records


def write_records(records: list[dict]) -> Path:
    RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RAW_DATA_DIR / f"source_records_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    with out_path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return out_path


def merge_records(records: list[dict], dry_run: bool) -> dict:
    black = read_domain_file(BLACK_FILE)
    white = read_domain_file(WHITE_FILE)
    before_black = len(black)
    before_white = len(white)

    for record in records:
        domain = record["domain"]
        if record["label"] == 1:
            black.add(domain)
        elif record["label"] == 0:
            white.add(domain)

    if not dry_run:
        write_domain_file(BLACK_FILE, black)
        write_domain_file(WHITE_FILE, white)

    return {
        "black_before": before_black,
        "black_after": len(black),
        "black_added": len(black) - before_black,
        "white_before": before_white,
        "white_after": len(white),
        "white_added": len(white) - before_white,
    }


def parse_source_arg(value: str) -> list[str]:
    if value == "default":
        return list(DEFAULT_SOURCES)
    if value == "all":
        return list(SOURCES)
    names = [part.strip() for part in value.split(",") if part.strip()]
    unknown = [name for name in names if name not in SOURCES]
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown source(s): {', '.join(unknown)}")
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect public phishing/legitimate seed feeds")
    parser.add_argument(
        "--sources",
        type=parse_source_arg,
        default=list(DEFAULT_SOURCES),
        help="default, all, or comma-separated source names",
    )
    parser.add_argument(
        "--per-source-limit",
        type=int,
        default=5000,
        help="Maximum records per source; use 0 for no limit",
    )
    parser.add_argument("--dry-run", action="store_true", help="Fetch and report without updating eval lists")
    parser.add_argument("--no-merge", action="store_true", help="Do not update eval_black_list/eval_white_list")
    args = parser.parse_args()

    per_source_limit = args.per_source_limit or None
    all_records: list[dict] = []
    for source_name in args.sources:
        print(f"[source] {source_name}: {SOURCES[source_name]['description']}")
        try:
            records = collect_one(source_name, per_source_limit)
        except Exception as exc:
            print(f"  ERROR: {exc}")
            continue
        print(f"  collected: {len(records)}")
        all_records.extend(records)

    seen = set()
    deduped = []
    for record in all_records:
        key = (record["label"], record["domain"], record["url"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)

    out_path = write_records(deduped)
    print(f"\nrecords written: {out_path}")
    print(f"records total: {len(deduped)}")

    if args.no_merge:
        return 0
    stats = merge_records(deduped, dry_run=args.dry_run)
    mode = "dry-run" if args.dry_run else "merged"
    print(f"\n{mode}:")
    print(f"  blacklist: {stats['black_before']} -> {stats['black_after']} (+{stats['black_added']})")
    print(f"  whitelist: {stats['white_before']} -> {stats['white_after']} (+{stats['white_added']})")
    return 0


if __name__ == "__main__":
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
