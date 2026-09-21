from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import sqlite3
import json
from datetime import datetime, timezone

DB_PATH = "control_plane.sqlite"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            api_token TEXT UNIQUE NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenant_modules (
            tenant_id INTEGER,
            module_name TEXT,
            is_enabled BOOLEAN,
            PRIMARY KEY (tenant_id, module_name)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS module_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER,
            hostname TEXT,
            module_name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            findings TEXT,
            FOREIGN KEY(tenant_id) REFERENCES tenants(id)
        )
    """)
    # Initialer Seed für Demo
    cur.execute("INSERT OR IGNORE INTO tenants (id, name, api_token) VALUES (1, 'Pilot-Systemhaus-Meier', 'aegis_test_token_001')")
    cur.execute("INSERT OR IGNORE INTO tenant_modules (tenant_id, module_name, is_enabled) VALUES (1, 'cis_hardening', 1)")
    cur.execute("INSERT OR IGNORE INTO tenant_modules (tenant_id, module_name, is_enabled) VALUES (1, 'backup_probe', 0)")
    conn.commit()
    conn.close()

app = FastAPI(title="Aegis Control Plane API", version="1.2.0")

@app.on_event("startup")
def startup():
    init_db()

def get_tenant_by_token(authorization: str) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Ungültiger Bearer Token")
    token = authorization.split(" ")[1]
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM tenants WHERE api_token = ?", (token,))
    tenant = cur.fetchone()
    conn.close()
    if not tenant:
        raise HTTPException(status_code=403, detail="Unautorisierter Zugriff")
    return dict(tenant)

@app.get("/api/v1/sync")
def sync_config(hostname: Optional[str] = None, os: Optional[str] = None, authorization: str = Header(None)):
    tenant = get_tenant_by_token(authorization)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT module_name, is_enabled FROM tenant_modules WHERE tenant_id = ?", (tenant["id"],))
    modules = {row["module_name"]: bool(row["is_enabled"]) for row in cur.fetchall()}
    conn.close()

    return {
        "status": "ok",
        "tenant_id": tenant["id"],
        "tenant_name": tenant["name"],
        "modules": modules
    }

class FindingItem(BaseModel):
    status: str
    code: str
    severity: str
    message: str
    compliance: Optional[List[str]] = []

class ResultPayload(BaseModel):
    hostname: str
    module_name: str
    findings: List[FindingItem]

@app.post("/api/v1/results")
def submit_results(payload: ResultPayload, authorization: str = Header(None)):
    tenant = get_tenant_by_token(authorization)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    findings_json = json.dumps([f.dict() for f in payload.findings])
    cur.execute("""
        INSERT INTO module_results (tenant_id, hostname, module_name, findings)
        VALUES (?, ?, ?, ?)
    """, (tenant["id"], payload.hostname, payload.module_name, findings_json))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Ergebnisse verarbeitet"}

class ToggleRequest(BaseModel):
    tenant_id: int
    module_name: str
    enable: bool

@app.post("/api/v1/admin/toggle")
def toggle_module(req: ToggleRequest):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO tenant_modules (tenant_id, module_name, is_enabled)
        VALUES (?, ?, ?)
        ON CONFLICT(tenant_id, module_name) DO UPDATE SET is_enabled = ?
    """, (req.tenant_id, req.module_name, int(req.enable), int(req.enable)))
    conn.commit()
    conn.close()
    return {"status": "success", "tenant_id": req.tenant_id, "module": req.module_name, "enabled": req.enable}

@app.get("/api/v1/admin/results/{tenant_id}")
def get_tenant_results(tenant_id: int):
    """Liefert alle Audit-Ergebnisse eines Mandanten für das Systemhaus-Dashboard."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT id, hostname, module_name, timestamp, findings 
        FROM module_results 
        WHERE tenant_id = ? 
        ORDER BY timestamp DESC
    """, (tenant_id,))
    
    results = []
    for row in cur.fetchall():
        item = dict(row)
        try:
            item["findings"] = json.loads(item["findings"])
        except Exception:
            item["findings"] = []
        results.append(item)
    conn.close()
    return {"status": "success", "tenant_id": tenant_id, "results": results}
