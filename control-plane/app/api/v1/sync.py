from fastapi import APIRouter, Depends, Header, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional
import json
import secrets

from app.core.database import get_db
from app.models.orm import Tenant, TenantModule, ModuleResult, HostDevice, WebhookConfig
from app.models.module_state import ResultPayload, RegisterHostRequest, RegisterHostResponse
from app.services.webhook import dispatch_webhook

router = APIRouter()

def verify_host_token(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> HostDevice:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Host-Bearer Token fehlt")
    token = authorization.split(" ")[1]
    host = db.query(HostDevice).filter(HostDevice.host_token == token).first()
    if not host:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Ungültiger Host-Token")
    return host

@router.post("/sync/register", response_model=RegisterHostResponse)
def register_host(payload: RegisterHostRequest, db: Session = Depends(get_db)):
    tenant = db.query(Tenant).filter(Tenant.enrollment_code == payload.enrollment_code).first()
    if not tenant:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ungültiger Enrollment-Code")

    host_token = f"aegis_host_{secrets.token_hex(32)}"
    host = HostDevice(
        tenant_id=tenant.id,
        hostname=payload.hostname,
        os_info=payload.os_info,
        host_token=host_token
    )
    db.add(host)
    db.commit()
    return {"status": "registered", "host_token": host_token}

@router.get("/sync/config")
def sync_config(
    hostname: Optional[str] = None, 
    os: Optional[str] = None, 
    host: HostDevice = Depends(verify_host_token),
    db: Session = Depends(get_db)
):
    modules_query = db.query(TenantModule).filter(TenantModule.tenant_id == host.tenant_id).all()
    modules_map = {m.module_name: m.is_enabled for m in modules_query}
    return {
        "status": "ok",
        "tenant_id": host.tenant_id,
        "hostname": host.hostname,
        "modules": modules_map
    }

@router.post("/sync/results")
def submit_results(
    payload: ResultPayload, 
    background_tasks: BackgroundTasks,
    host: HostDevice = Depends(verify_host_token),
    db: Session = Depends(get_db)
):
    findings_json = json.dumps([f.model_dump() for f in payload.findings])
    result_entry = ModuleResult(
        tenant_id=host.tenant_id,
        hostname=host.hostname,
        module_name=payload.module_name,
        findings=findings_json
    )
    db.add(result_entry)
    db.commit()

    needs_alert = any(
        f.status == 'FAIL' or f.severity in ['HIGH', 'CRITICAL'] 
        for f in payload.findings
    )

    if needs_alert:
        webhooks = db.query(WebhookConfig).filter(
            WebhookConfig.tenant_id == host.tenant_id, 
            WebhookConfig.is_active == True
        ).all()
        
        if webhooks:
            alert_payload = payload.model_dump()
            alert_payload["tenant_id"] = host.tenant_id
            for wh in webhooks:
                background_tasks.add_task(dispatch_webhook, wh.url, wh.secret_token, alert_payload)

    return {"status": "success", "message": "Audit-Ergebnisse gespeichert."}
