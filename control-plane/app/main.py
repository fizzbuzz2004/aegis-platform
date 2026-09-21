from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any
import sqlite3
import os
import json
from datetime import datetime

DB_PATH = "control_plane.sqlite"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Bestehende Tabellen
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
    # NEU: Tabelle für Audit-Ergebnisse zur zentralen Auswertung
    cur.execute("""
        CREATE TABLE IF NOT EXISTS module_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER,
            module_name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            findings TEXT,
            FOREIGN KEY(tenant_id) REFERENCES tenants(id)
        )
    """)
    # Seed Initial Tenant
    cur.execute("INSERT OR IGNORE INTO tenants (id, name, api_token) VALUES (1, 'Pilot-Systemhaus-Meier', 'aegis_test_token_001')")
    cur.execute("INSERT OR IGNORE INTO tenant_modules (tenant_id, module_name, is_enabled) VALUES (1, 'cis_hardening', 1)")
    cur.execute("INSERT OR IGNORE INTO tenant_modules (tenant_id, module_name, is_enabled) VALUES (1, 'backup_probe', 0)")
    conn.commit()
    conn.close()

app = FastAPI(title="Aegis Control Plane")

@app.on_event("startup")
def startup():
    init_db()

def get_tenant_by_token(authorization: str) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer token")
    token = authorization.split(" ")[1]
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM tenants WHERE api_token = ?", (token,))
    tenant = cur.fetchone()
    conn.close()
    if not tenant:
        raise HTTPException(status_code=403, detail="Invalid API Token")
    return dict(tenant)

@app.get("/api/v1/sync")
def sync_config(authorization: str = Header(None)):
    tenant = get_tenant_by_token(authorization)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT module_name, is_enabled FROM tenant_modules WHERE tenant_id = ?", (tenant["id"],))
    modules = {row["module_name"]: bool(row["is_enabled"]) for row in cur.fetchall()}
    conn.close()

    return {"status": "ok", "tenant": tenant["name"], "modules": modules}

# NEU: Endpunkt zum Empfangen der Ergebnisse vom Agenten
class ResultPayload(BaseModel):
    module_name: str
    findings: List[str]

@app.post("/api/v1/results")
def submit_results(payload: ResultPayload, authorization: str = Header(None)):
    tenant = get_tenant_by_token(authorization)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO module_results (tenant_id, module_name, findings)
        VALUES (?, ?, ?)
    """, (tenant["id"], payload.module_name, json.dumps(payload.findings)))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Results stored successfully"}

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
