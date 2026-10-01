from fastapi import APIRouter, Depends, Header, HTTPException, status, BackgroundTasks, Request, Response
from sqlalchemy.orm import Session
from typing import Optional, Dict
import json
import secrets
import re
from urllib.parse import urlsplit
from datetime import datetime, timezone

from app.core.config import settings
from app.core.database import get_db
from app.models.orm import Tenant, TenantModule, ModuleResult, HostDevice, WebhookConfig
from app.models.module_state import ResultPayload, RegisterHostRequest, RegisterHostResponse
from app.services.psa_adapter import PSADispatcher
from app.core.limiter import limiter

router = APIRouter()

def verify_host_token(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> HostDevice:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Host-Bearer Token fehlt oder ungültig")
    
    token = authorization.split(" ")[1]
    host = db.query(HostDevice).filter(HostDevice.host_token == token).first()
    if not host:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unbekanntes oder revokiertes Gerät")
    return host

@router.post("/agents/register", response_model=RegisterHostResponse)
@limiter.limit("30/minute")
def register_agent(
    request: Request,
    payload: RegisterHostRequest,
    db: Session = Depends(get_db)
):
    tenant = db.query(Tenant).filter(Tenant.enrollment_code == payload.enrollment_code).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Ungültiger Enrollment-Code"
        )
    
    # Generierung eines kryptografisch sicheren Tokens (64 Hex-Zeichen)
    secure_host_token = f"ath_{secrets.token_hex(32)}"
    
    existing_host = db.query(HostDevice).filter(
        HostDevice.tenant_id == tenant.id,
        HostDevice.hostname == payload.hostname
    ).first()

    if existing_host:
        existing_host.host_token = secure_host_token
        existing_host.os_info = payload.os_info
    else:
        new_host = HostDevice(
            tenant_id=tenant.id,
            hostname=payload.hostname,
            os_info=payload.os_info,
            host_token=secure_host_token
        )
        db.add(new_host)

    db.commit()
    return RegisterHostResponse(status="success", host_token=secure_host_token)

@router.get("/agents/desired-state", response_model=Dict[str, bool])
def get_desired_state(
    host: HostDevice = Depends(verify_host_token),
    db: Session = Depends(get_db)
):
    modules = db.query(TenantModule).filter(TenantModule.tenant_id == host.tenant_id).all()
    state = {m.module_name: m.is_enabled for m in modules}
    return state

@router.get("/agents/update")
def get_agent_update(
    response: Response,
    host: HostDevice = Depends(verify_host_token),
):
    response.headers["Cache-Control"] = "no-store"
    version = settings.AGENT_UPDATE_VERSION
    download_url = settings.AGENT_UPDATE_URL
    sha256 = settings.AGENT_UPDATE_SHA256
    os_info = settings.AGENT_UPDATE_OS_INFO

    if not any((version, download_url, sha256, os_info)):
        return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"})
    if not all((version, download_url, sha256, os_info)):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Agent-Update unvollständig konfiguriert")

    if host.os_info != os_info:
        return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"})

    try:
        parsed_url = urlsplit(download_url)
        parsed_url.port
    except ValueError:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Agent-Update-Konfiguration ungültig")
    if (
        not re.fullmatch(
            r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
            r"(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
            r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?"
            r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
            version,
        )
        or parsed_url.scheme != "https"
        or not parsed_url.hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
        or not re.fullmatch(r"[0-9a-fA-F]{64}", sha256)
        or not re.fullmatch(r"(?:linux|windows|darwin)-(?:amd64|arm64)", os_info)
    ):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Agent-Update-Konfiguration ungültig")

    return {"version": version, "download_url": download_url, "sha256": sha256.lower(), "os_info": os_info}

@router.post("/sync/results")
@limiter.limit("200/minute") 
def submit_results(
    request: Request,
    payload: ResultPayload, 
    background_tasks: BackgroundTasks,
    host: HostDevice = Depends(verify_host_token),
    db: Session = Depends(get_db)
):
    findings_json = json.dumps([f.model_dump() for f in payload.findings])
    
    previous_result = db.query(ModuleResult).filter(
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

    source_ip = request.client.host if request.client else "unknown"
    result_entry = ModuleResult(
        tenant_id=host.tenant_id,
        hostname=host.hostname,
        module_name=payload.module_name,
        findings=findings_json,
        audit_meta={"source_ip": source_ip, "received_at": datetime.now(timezone.utc).isoformat()}
    )
    db.add(result_entry)
    db.commit()

    webhooks = db.query(WebhookConfig).filter(
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
                previous_state_failed=previous_failed,
                db=db
            )

    return {"status": "success", "message": "Audit-Ergebnisse revisionssicher gespeichert."}
