#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tauri::{Manager, Window};

#[derive(Serialize, Deserialize, Clone)]
struct DBStats {
    blacklist: i32,
    whitelist: i32,
    raw_html: i32,
}

#[derive(Serialize, Deserialize, Clone)]
struct FeatureStats {
    total: i32,
    phishing: i32,
    legitimate: i32,
    with_text: i32,
}

#[derive(Serialize, Deserialize, Clone)]
struct Stats {
    database: DBStats,
    features: FeatureStats,
    brands: HashMap<String, i32>,
}

fn get_project_dir() -> PathBuf {
    // Tự động tìm thư mục gốc chứa data và crawl_python bằng cách duyệt ngược lên trên
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for _ in 0..6 {
        if dir.join("data").is_dir() && dir.join("crawl_python").is_dir() {
            return dir;
        }
        if let Some(parent) = dir.parent() {
            dir = parent.to_path_buf();
        } else {
            break;
        }
    }
    
    // Thử dùng thư mục của file exe chạy
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let mut d = parent.to_path_buf();
            for _ in 0..6 {
                if d.join("data").is_dir() && d.join("crawl_python").is_dir() {
                    return d;
                }
                if let Some(p) = d.parent() {
                    d = p.to_path_buf();
                } else {
                    break;
                }
            }
        }
    }
    PathBuf::from(".")
}

#[tauri::command]
fn get_stats() -> Result<Stats, String> {
    let project_dir = get_project_dir();
    let db_path = project_dir.join("data").join("dedup_cache.db");
    let features_path = project_dir.join("data").join("features").join("seed_features.jsonl");

    let mut db_stats = DBStats {
        blacklist: 0,
        whitelist: 0,
        raw_html: 0,
    };

    // 1. Đọc từ SQLite database
    if db_path.exists() {
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            let mut stmt = conn
                .prepare("SELECT list_type, count(*) FROM seen_urls GROUP BY list_type")
                .map_err(|e| e.to_string())?;
            
            let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
            while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                let list_type: String = row.get(0).map_err(|e| e.to_string())?;
                let count: i32 = row.get(1).map_err(|e| e.to_string())?;
                match list_type.as_str() {
                    "blacklist" => db_stats.blacklist = count,
                    "whitelist" => db_stats.whitelist = count,
                    "raw_html" => db_stats.raw_html = count,
                    _ => {}
                }
            }
        }
    }

    let mut feat_stats = FeatureStats {
        total: 0,
        phishing: 0,
        legitimate: 0,
        with_text: 0,
    };
    let mut brands_map: HashMap<String, i32> = HashMap::new();

    // 2. Đọc từ file seed_features.jsonl
    if features_path.exists() {
        if let Ok(file) = File::open(&features_path) {
            let reader = BufReader::new(file);
            for line_res in reader.lines() {
                if let Ok(line) = line_res {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                        feat_stats.total += 1;
                        if val.get("label").and_then(|l| l.as_i64()) == Some(1) {
                            feat_stats.phishing += 1;
                        } else {
                            feat_stats.legitimate += 1;
                        }

                        if let Some(text) = val.get("text").and_then(|t| t.as_str()) {
                            if !text.trim().is_empty() {
                                feat_stats.with_text += 1;
                            }
                        }

                        if let Some(matches) = val.get("brand_matches").and_then(|m| m.as_array()) {
                            for m in matches {
                                if let Some(brand) = m.get("brand").and_then(|b| b.as_str()) {
                                    *brands_map.entry(brand.to_string()).or_insert(0) += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Stats {
        database: db_stats,
        features: feat_stats,
        brands: brands_map,
    })
}

#[tauri::command]
fn get_records(label_filter: String, search_query: String) -> Result<Vec<Value>, String> {
    let project_dir = get_project_dir();
    let features_path = project_dir.join("data").join("features").join("seed_features.jsonl");
    let mut records = Vec::new();

    if !features_path.exists() {
        return Ok(records);
    }

    let search_lower = search_query.to_lowercase();

    let file = File::open(&features_path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);

    for line_res in reader.lines() {
        if let Ok(line) = line_res {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(mut val) = serde_json::from_str::<Value>(trimmed) {
                // Lọc nhãn
                let label = val.get("label").and_then(|l| l.as_i64()).unwrap_or(-1);
                if label_filter == "phishing" && label != 1 {
                    continue;
                }
                if label_filter == "legitimate" && label != 0 {
                    continue;
                }

                // Tìm kiếm
                let domain = val.get("domain").and_then(|d| d.as_str()).unwrap_or("").to_lowercase();
                let title = val.get("title").and_then(|t| t.as_str()).unwrap_or("").to_lowercase();
                let text = val.get("text").and_then(|t| t.as_str()).unwrap_or("").to_lowercase();

                if !search_query.is_empty() 
                    && !domain.contains(&search_lower) 
                    && !title.contains(&search_lower) 
                    && !text.contains(&search_lower) 
                {
                    continue;
                }

                // Cắt bớt văn bản thô để tránh response quá lớn ảnh hưởng tới IPC
                if let Some(obj) = val.as_object_mut() {
                    if let Some(text_val) = obj.get_mut("text") {
                        if let Some(text_str) = text_val.as_str() {
                            if text_str.chars().count() > 1200 {
                                let short: String = text_str.chars().take(1200).collect();
                                obj.insert("text_preview".to_string(), Value::String(format!("{}...", short)));
                            }
                        }
                    }
                }

                records.push(val);
            }
        }
    }

    Ok(records)
}

#[tauri::command]
async fn run_pipeline(window: Window) -> Result<(), String> {
    let project_dir = get_project_dir();
    
    // Tìm file exe python hoặc chạy lệnh python chuẩn
    let python_cmd = if cfg!(target_os = "windows") { "python" } else { "python3" };
    let pipeline_script = project_dir.join("crawl_python").join("phishing_mvp_pipeline.py");

    window.emit("pipeline-log", "Bắt đầu chạy pipeline kết xuất đặc trưng...\n").map_err(|e| e.to_string())?;

    let mut child = Command::new(python_cmd)
        .arg(pipeline_script)
        .arg("all")
        .arg("--phishing-limit")
        .arg("150")
        .arg("--legitimate-limit")
        .arg("150")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(&project_dir)
        .spawn()
        .map_err(|e| format!("Không thể chạy python: {}", e))?;

    let stdout = child.stdout.take().ok_or("Không thể mở stdout của tiến trình python")?;
    let reader = BufReader::new(stdout);

    // Stream logs qua IPC
    for line_res in reader.lines() {
        if let Ok(line) = line_res {
            let log_line = format!("{}\n", line);
            println!("{}", log_line);
            window.emit("pipeline-log", log_line).map_err(|e| e.to_string())?;
        }
    }

    let status = child.wait().map_err(|e| e.to_string())?;
    let finish_msg = format!("\nPipeline kết thúc với mã thoát: {}\n", status.code().unwrap_or(-1));
    window.emit("pipeline-log", finish_msg).map_err(|e| e.to_string())?;

    Ok(())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_stats, get_records, run_pipeline])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
