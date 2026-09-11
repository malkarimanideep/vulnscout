from fastapi import FastAPI, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import sqlite3
import json
from scanner import scan_host

app = FastAPI(title="VulnScout API")

def init_db():
    with sqlite3.connect("scans.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

init_db()

@app.get("/")
def serve_ui():
    return FileResponse("static/index.html")

@app.post("/scan")
def start_scan(target: str, background_tasks: BackgroundTasks):
    def run_task():
        report_data = scan_host(target)
        with sqlite3.connect("scans.db") as conn:
            conn.execute(
                "INSERT INTO reports (target, data) VALUES (?, ?)",
                (target, json.dumps(report_data))
            )
    background_tasks.add_task(run_task)
    return {"status": "scan initiated", "target": target}

@app.get("/reports")
def get_reports():
    with sqlite3.connect("scans.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, target, data, created_at FROM reports ORDER BY id DESC")
        rows = cur.fetchall()

        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "target": row[1],
                "data": json.loads(row[2]),
                "created_at": row[3]
            })
        return {"scans": results}

app.mount("/static", StaticFiles(directory="static"), name="static")
