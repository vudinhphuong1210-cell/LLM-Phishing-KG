# Crawler choice

Generated at: 2026-06-17T10:47:01+00:00

- Primary crawler: crawl_python/fetch_html.py followed by crawl_python/extract_text.py.
- Fallback crawlers: Firecrawl or Playwright are disabled by default and should be used only for snapshot evidence.
- Dataset/features consume only crawl_python/html/processed/*_text_*.jsonl.
- Short phishing pages are kept when form or password-field evidence exists.
- Crawler safety policy: no form submission, no credential entry, no login bypass, no OTP/password collection.
