from fastapi import APIRouter, Depends, Header, HTTPException, status, BackgroundTasks, Request
from sqlalchemy.orm import Session
from typing import Optional, Any
import json
import secrets
from datetime import datetime, timezone

from app.core.database import get_db
from app.models.orm import Tenant, TenantModule, ModuleResult, HostDevice, WebhookConfig
from app.models.module_state import ResultPayload, RegisterHostRequest, RegisterHostResponse
from app.services.psa_adapter import PSADispatcher
from app.main import limiter 

router = APIRouter()

def verify_host_token(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> HostDevice:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Host-Bearer Token fehlt oder ungültig")
    
    token = authorization.split(" ")[1]
    host = db.query(HostDevice).filter(HostDevice.host_token == token).first()
    if not host:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unbekanntes oder kompromittiertes Gerät")
    return host

def get_tenant_scoped_db(host: HostDevice, db: Session) -> Session:
    """Stellt sicher, dass DB-Operationen strickt auf den Tenant des Hosts beschränkt sind."""
    tenant = db.query(Tenant).filter(Tenant.id == host.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant-Isolationsfehler")
    return db

@router.post("/sync/results")
@limiter.limit("200/minute") 
def submit_results(
    request: Request,
    payload: ResultPayload, 
    background_tasks: BackgroundTasks,
    host: HostDevice = Depends(verify_host_token),
    db: Session = Depends(get_db)
):
    scoped_db = get_tenant_scoped_db(host, db)
    findings_json = json.dumps([f.model_dump() for f in payload.findings])
    
    # Historischen Status für Auto-Resolve prüfen
    previous_result = scoped_db.query(ModuleResult).filter(
        ModuleResult.tenant_id == host.tenant_id,
        ModuleResult.hostname == host.hostname,
        ModuleResult.module_name == payload.module_name
    ).order_by(ModuleResult.timestamp.desc()).first()

    previous_failed = False
    if previous_result:
        try:
            prev_findings = json.loads(previous_result.findings)
            previous_failed = any(
                f.get('status') == 'FAIL' or f.get('severity') in ['HIGH', 'CRITICAL'] 
                for f in prev_findings
            )
        except Exception:
            pass

    # Neues Result revisionssicher speichern
    result_entry = ModuleResult(
        tenant_id=host.tenant_id,
        hostname=host.hostname,
        module_name=payload.module_name,
        findings=findings_json,
        audit_meta={"source_ip": request.client.host, "received_at": datetime.now(timezone.utc).isoformat()}
    )
    scoped_db.add(result_entry)
    scoped_db.commit()

    # Webhooks & PSA Dispatch (Bidirektional)
    webhooks = scoped_db.query(WebhookConfig).filter(
        WebhookConfig.tenant_id == host.tenant_id, 
        WebhookConfig.is_active == True
    ).all()
    
    if webhooks:
        alert_payload = payload.model_dump()
        alert_payload["tenant_id"] = host.tenant_id
        for wh in webhooks:
            background_tasks.add_task(
                PSADispatcher.dispatch_event, 
                url=wh.url, 
                secret_token=wh.secret_token, 
                payload=alert_payload,
                previous_state_failed=previous_failed
            )

    return {"status": "success", "message": "Audit-Ergebnisse revisionssicher gespeichert."}
