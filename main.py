import aiohttp
import asyncio
import json
import re
import random
import logging
import time
import sqlite3
import hashlib
import os
from typing import Dict, List, Optional
from urllib.parse import urlparse
from fastapi import FastAPI, WebSocket, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from pydantic import BaseModel

# إعدادات التسجيل
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)

# إعدادات عامة
DATABASE = "scan_results.db"
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# نماذج البيانات
class ScanRequest(BaseModel):
    url: str

# تهيئة قاعدة البيانات
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (scan_id TEXT PRIMARY KEY, 
                  url TEXT, 
                  status TEXT, 
                  start_time REAL,
                  end_time REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                 (vuln_id TEXT PRIMARY KEY,
                  scan_id TEXT,
                  type TEXT,
                  severity TEXT,
                  details TEXT,
                  timestamp REAL,
                  FOREIGN KEY(scan_id) REFERENCES scans(scan_id))''')
    conn.commit()
    conn.close()

init_db()

class AdvancedScanner:
    def __init__(self, url: str):
        self.url = url
        self.host = urlparse(url).hostname
        self.scan_id = hashlib.sha256(f"{url}{time.time()}".encode()).hexdigest()[:12]
        self.session = aiohttp.ClientSession()
        self._save_scan('running')

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.session.close()
        self._save_scan('completed')

    def _save_scan(self, status: str):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        if status == 'running':
            c.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?)",
                     (self.scan_id, self.url, status, time.time(), None))
        else:
            c.execute("UPDATE scans SET status=?, end_time=? WHERE scan_id=?",
                     (status, time.time(), self.scan_id))
        conn.commit()
        conn.close()

    async def _save_vulnerability(self, vuln: dict):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        vuln_id = hashlib.sha256(f"{self.scan_id}{vuln['type']}".encode()).hexdigest()[:12]
        c.execute("INSERT INTO vulnerabilities VALUES (?, ?, ?, ?, ?, ?)",
                 (vuln_id, self.scan_id, vuln['type'], vuln['severity'], 
                  json.dumps(vuln['details']), time.time()))
        conn.commit()
        conn.close()

    async def full_scan(self):
        # محاكاة عملية الفحص (يمكن إضافة المنطق الحقيقي هنا)
        vulnerabilities = [
            {'type': 'SQLi', 'severity': 'High', 'details': 'Found SQL injection vulnerability'},
            {'type': 'XSS', 'severity': 'Medium', 'details': 'Possible XSS detected'},
        ]
        
        for vuln in vulnerabilities:
            await self._save_vulnerability(vuln)
            await asyncio.sleep(1)  # محاكاة التأخير

# واجهة الويب
@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <html>
    <head>
        <title>أداة الفحص الأمني المتقدمة</title>
        <link rel="stylesheet" href="/static/style.css">
    </head>
    <body>
        <h1>أداة الفحص الأمني المتقدمة</h1>
        <form id="scanForm">
            <input type="url" id="targetUrl" required placeholder="أدخل الرابط هنا">
            <button type="submit">بدء الفحص</button>
        </form>
        <div id="results"></div>
        <script src="/static/app.js"></script>
    </body>
    </html>
    """

@app.post("/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scanner = AdvancedScanner(request.url)
    background_tasks.add_task(scanner.full_scan)
    return {"scan_id": scanner.scan_id}

@app.websocket("/ws/{scan_id}")
async def websocket_updates(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    conn = sqlite3.connect(DATABASE)
    
    try:
        while True:
            c = conn.cursor()
            c.execute("SELECT * FROM vulnerabilities WHERE scan_id=?", (scan_id,))
            vulns = [dict(row) for row in c.fetchall()]
            await websocket.send_json(vulns)
            await asyncio.sleep(1)
    finally:
        conn.close()

@app.get("/results/{scan_id}", response_class=HTMLResponse)
async def get_results(scan_id: str):
    return f"""
    <html>
    <head>
        <title>نتائج الفحص - {scan_id}</title>
        <link rel="stylesheet" href="/static/style.css">
    </head>
    <body>
        <h1>نتائج الفحص</h1>
        <div id="results"></div>
        <script>
            const ws = new WebSocket(`ws://${{window.location.host}}/ws/{scan_id}`);
            ws.onmessage = (event) => {{
                const data = JSON.parse(event.data);
                document.getElementById('results').innerHTML = `
                    <pre>${{JSON.stringify(data, null, 2)}}</pre>
                `;
            }};
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)