#!/usr/bin/env python3
import http.server
import socketserver
import json
import sqlite3
import urllib.parse
from pathlib import Path
import subprocess
import threading
import sys
import time
from datetime import datetime, timedelta, timezone

PORT = 8080
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "dedup_cache.db"
FEATURES_PATH = BASE_DIR / "data" / "features" / "seed_features.jsonl"
DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboard"

# Fix console encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

server_logs = []
server_logs_lock = threading.Lock()

class ServerLogCapture:
    def __init__(self, original_stream):
        self.original_stream = original_stream

    def write(self, message):
        self.original_stream.write(message)
        if message:
            with server_logs_lock:
                server_logs.append(message)
                if len(server_logs) > 1000:
                    server_logs.pop(0)

    def flush(self):
        self.original_stream.flush()

sys.stdout = ServerLogCapture(sys.stdout)
sys.stderr = ServerLogCapture(sys.stderr)

pipeline_running = False
pipeline_log = []
pipeline_status = {
    "running": False,
    "current_step": 0,
    "total_steps": 6,
    "step_name": "Sẵn sàng",
    "status": "idle"  # idle, running, completed, error
}


# Load / Save Scheduler Config
SCHEDULER_CONFIG_PATH = BASE_DIR / "configs" / "scheduler_config.json"

scheduler_config = {
    "interval_hours": 0,  # 0 means disabled / manual
    "last_run": None      # ISO timestamp
}

def load_scheduler_config():
    global scheduler_config
    if SCHEDULER_CONFIG_PATH.exists():
        try:
            with open(SCHEDULER_CONFIG_PATH, "r", encoding="utf-8") as f:
                scheduler_config.update(json.load(f))
        except Exception as e:
            print(f"Error loading scheduler config: {e}")
    else:
        try:
            SCHEDULER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            save_scheduler_config()
        except Exception as e:
            print(f"Error creating config dir: {e}")

def save_scheduler_config():
    try:
        SCHEDULER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(SCHEDULER_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(scheduler_config, f, indent=4)
    except Exception as e:
        print(f"Error saving scheduler config: {e}")

def get_next_run_time():
    interval = scheduler_config.get("interval_hours", 0)
    if interval <= 0:
        return None
    last_run_str = scheduler_config.get("last_run")
    if not last_run_str:
        return datetime.now(timezone.utc).isoformat()
    try:
        last_run = datetime.fromisoformat(last_run_str)
        if last_run.tzinfo is None:
            last_run = last_run.replace(tzinfo=timezone.utc)
        next_run = last_run + timedelta(hours=interval)
        return next_run.isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()

def scheduler_loop():
    global pipeline_running, scheduler_config
    while True:
        time.sleep(10)
        interval = scheduler_config.get("interval_hours", 0)
        if interval <= 0:
            continue
        if pipeline_running:
            continue
        
        last_run_str = scheduler_config.get("last_run")
        should_run = False
        if not last_run_str:
            should_run = True
        else:
            try:
                last_run = datetime.fromisoformat(last_run_str)
                if last_run.tzinfo is None:
                    last_run = last_run.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                if now - last_run >= timedelta(hours=interval):
                    should_run = True
            except Exception as e:
                print(f"Error parsing last_run in scheduler: {e}")
                should_run = True
                
        if should_run:
            print(f"[Scheduler] Time elapsed. Triggering pipeline...")
            threading.Thread(target=run_pipeline_thread).start()

def run_pipeline_thread():
    global pipeline_running, pipeline_log, scheduler_config, pipeline_status
    pipeline_running = True
    pipeline_status["running"] = True
    pipeline_status["status"] = "running"
    
    # Update last run timestamp
    scheduler_config["last_run"] = datetime.now(timezone.utc).isoformat()
    save_scheduler_config()
    pipeline_log = ["Starting full crawler and feature extraction pipeline...\n\n"]
    
    steps = [
        ("Step 1: Harvesting new domains from online APIs (crawl.py)", 
         [sys.executable, "-u", str(BASE_DIR / "crawl_python" / "crawl.py"), "--source", "black", "--max-pages", "1"]),
        
        ("Step 1.5: Synchronizing domains to SQLite database (clean_lists.py)",
         [sys.executable, "-u", str(BASE_DIR / "crawl_python" / "clean_lists.py"), "--source", "black"]),
        
        ("Step 2: Fetching HTML content of new domains online (fetch_html.py)", 
         [sys.executable, "-u", str(BASE_DIR / "crawl_python" / "fetch_html.py"), "--source", "black", "--limit", "10", "--workers", "5", "--min-words", "10"]),
        
        ("Step 3: Cleaning raw HTML files (clean_blacklist.py)", 
         [sys.executable, "-u", str(BASE_DIR / "crawl_python" / "clean_blacklist.py"), "--source", "black", "--min-words", "10"]),
        
        ("Step 4: Extracting plain text from clean HTML (extract_text.py)", 
         [sys.executable, "-u", str(BASE_DIR / "crawl_python" / "extract_text.py"), "--source", "black"]),
        
        ("Step 5: Standardizing dataset and feature extraction (phishing_mvp_pipeline.py)", 
         [sys.executable, "-u", str(BASE_DIR / "crawl_python" / "phishing_mvp_pipeline.py"), "all", "--phishing-limit", "150", "--legitimate-limit", "150"])
    ]
    
    pipeline_status["total_steps"] = len(steps)
    all_steps_ok = True
    
    try:
        for idx, (name, cmd) in enumerate(steps):
            pipeline_status["current_step"] = idx + 1
            pipeline_status["step_name"] = name
            
            pipeline_log.append(f"\n=========================================\n{name}\n=========================================\n")
            print(f"Running: {name}")
            
            import os
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(BASE_DIR),
                encoding="utf-8",
                errors="replace",
                env=env
            )
            for line in process.stdout:
                pipeline_log.append(line)
                print(line, end="")
            process.wait()
            
            if process.returncode != 0:
                pipeline_log.append(f"\n[WARNING] {name} exited with code {process.returncode}\n")
                all_steps_ok = False
                
        if all_steps_ok:
            pipeline_log.append("\n=========================================\nPipeline Execution Completed Successfully!\n=========================================\n")
        else:
            pipeline_log.append("\n=========================================\nPipeline Completed with Warnings/Errors.\n=========================================\n")
    except Exception as e:
        pipeline_log.append(f"\n[ERROR] Pipeline failed: {str(e)}\n")
        all_steps_ok = False
    finally:
        pipeline_running = False
        pipeline_status["running"] = False
        pipeline_status["status"] = "completed" if all_steps_ok else "error"


class DashboardHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/stats":
            self.get_stats()
        elif path == "/api/records":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            self.get_records(query_params)
        elif path == "/api/pipeline-status":
            self.get_pipeline_status()
        elif path == "/api/scheduler-info":
            self.get_scheduler_info()
        elif path == "/api/server-logs":
            self.get_server_logs()
        elif path.startswith("/screenshots/"):
            filename = Path(path).name
            screenshot_file = BASE_DIR / "crawl_python" / "html" / "screenshots" / filename
            if screenshot_file.is_file():
                self.send_response(200)
                if filename.endswith(".png"):
                    self.send_header("Content-type", "image/png")
                else:
                    self.send_header("Content-type", "application/octet-stream")
                self.end_headers()
                with screenshot_file.open("rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "Screenshot not found")
        elif path == "/" or path == "/index.html":
            self.serve_index()
        else:
            # Fallback to serving files from dashboard dir if they exist
            file_path = DASHBOARD_DIR / path.lstrip("/")
            if file_path.is_file() and DASHBOARD_DIR in file_path.resolve().parents:
                super().do_GET()
            else:
                self.serve_index()

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/run-pipeline":
            self.trigger_pipeline()
        elif path == "/api/scheduler-config":
            self.update_scheduler_config()
        elif path == "/api/clear-server-logs":
            self.clear_server_logs()
        else:
            self.send_error(404, "Not Found")

    def serve_index(self):
        index_file = DASHBOARD_DIR / "index.html"
        if not index_file.is_file():
            self.send_error(404, "Index HTML dashboard file not found")
            return
        
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        with index_file.open("rb") as f:
            self.wfile.write(f.read())

    def get_stats(self):
        stats = {
            "database": {"blacklist": 0, "whitelist": 0, "raw_html": 0},
            "features": {"total": 0, "phishing": 0, "legitimate": 0, "with_text": 0},
            "brands": {}
        }

        # Query SQLite
        if DB_PATH.exists():
            try:
                with sqlite3.connect(DB_PATH, timeout=5.0) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT list_type, count(*) FROM seen_urls GROUP BY list_type")
                    for r in cursor.fetchall():
                        stats["database"][r[0]] = r[1]
            except Exception as e:
                print(f"Error reading SQLite stats: {e}")

        # Query Features
        if FEATURES_PATH.exists():
            try:
                with FEATURES_PATH.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                            stats["features"]["total"] += 1
                            if rec.get("label") == 1:
                                stats["features"]["phishing"] += 1
                            else:
                                stats["features"]["legitimate"] += 1
                            
                            if rec.get("text"):
                                stats["features"]["with_text"] += 1

                            for bm in rec.get("brand_matches", []):
                                bname = bm.get("brand")
                                stats["brands"][bname] = stats["brands"].get(bname, 0) + 1
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"Error reading features stats: {e}")

        self.send_response(200)
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(stats, ensure_ascii=False).encode("utf-8"))

    def get_records(self, query_params):
        search = query_params.get("search", [""])[0].lower()
        label_filter = query_params.get("label", ["all"])[0]
        brand_filter = query_params.get("brand", ["all"])[0]

        records = []
        if FEATURES_PATH.exists():
            try:
                with FEATURES_PATH.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                            
                            # Filter label
                            if label_filter == "phishing" and rec.get("label") != 1:
                                continue
                            if label_filter == "legitimate" and rec.get("label") != 0:
                                continue

                            # Filter brand
                            if brand_filter != "all":
                                brands = [b.get("brand") for b in rec.get("brand_matches", [])]
                                if brand_filter not in brands:
                                    continue

                            # Filter search
                            domain = rec.get("domain", "").lower()
                            title = (rec.get("title") or "").lower()
                            text = (rec.get("text") or "").lower()
                            if search and (search not in domain and search not in title and search not in text):
                                continue

                            # Simplify text payload to keep response sizes reasonable
                            rec_copy = dict(rec)
                            if rec_copy.get("text") and len(rec_copy["text"]) > 1000:
                                rec_copy["text_preview"] = rec_copy["text"][:1000] + "..."
                            
                            records.append(rec_copy)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"Error reading records: {e}")

        self.send_response(200)
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(records, ensure_ascii=False).encode("utf-8"))

    def get_pipeline_status(self):
        status = {
            "running": pipeline_running,
            "current_step": pipeline_status.get("current_step", 0),
            "total_steps": pipeline_status.get("total_steps", 6),
            "step_name": pipeline_status.get("step_name", "Sẵn sàng"),
            "status": pipeline_status.get("status", "idle"),
            "logs": "".join(pipeline_log)
        }
        self.send_response(200)
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(status, ensure_ascii=False).encode("utf-8"))

    def trigger_pipeline(self):
        global pipeline_running
        if pipeline_running:
            self.send_response(400)
            self.send_header("Content-type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Pipeline already running"}).encode("utf-8"))
            return

        threading.Thread(target=run_pipeline_thread).start()
        self.send_response(200)
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "started"}).encode("utf-8"))

    def get_scheduler_info(self):
        status = {
            "interval_hours": scheduler_config.get("interval_hours", 0),
            "last_run": scheduler_config.get("last_run"),
            "next_run": get_next_run_time(),
            "running": pipeline_running
        }
        self.send_response(200)
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(status, ensure_ascii=False).encode("utf-8"))

    def update_scheduler_config(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        try:
            data = json.loads(post_data.decode('utf-8'))
            interval = int(data.get("interval_hours", 0))
            scheduler_config["interval_hours"] = interval
            save_scheduler_config()
            
            self.send_response(200)
            self.send_header("Content-type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "config": scheduler_config}).encode("utf-8"))
        except Exception as e:
            self.send_response(400)
            self.send_header("Content-type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def get_server_logs(self):
        with server_logs_lock:
            logs = "".join(server_logs)
        self.send_response(200)
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps({"logs": logs}, ensure_ascii=False).encode("utf-8"))

    def clear_server_logs(self):
        global server_logs
        with server_logs_lock:
            server_logs.clear()
        self.send_response(200)
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "cleared"}).encode("utf-8"))

def main():
    DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)
    load_scheduler_config()
    
    # Start daemon scheduler thread
    scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
    scheduler_thread.start()
    
    handler = DashboardHTTPRequestHandler
    
    # Allow address reuse
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"\n=======================================================")
        print(f"  PHISHING INTELLIGENCE PIPELINE DASHBOARD IS ONLINE  ")
        print(f"  URL: http://localhost:{PORT}                        ")
        print(f"=======================================================\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard server...")
            httpd.server_close()

if __name__ == "__main__":
    main()
