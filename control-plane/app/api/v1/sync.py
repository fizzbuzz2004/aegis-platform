# control-plane/app/api/v1/sync.py
from fastapi import APIRouter, Depends, Header, HTTPException, status, BackgroundTasks, Request, Response
from sqlalchemy.orm import Session
from typing import Optional, Dict
import json
import secrets
import re
import hmac
import base64
from urllib.parse import urlsplit
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.database import get_db
from app.core.mtls import (
    get_client_certificate_fingerprint, 
    sign_agent_csr_internally, 
    extract_fingerprint_from_cert_pem
)
from app.models.orm import Tenant, TenantModule, ModuleResult, HostDevice, WebhookConfig
from app.models.module_state import ResultPayload, RegisterHostRequest, RegisterHostResponse
from app.services.backup_alerts import evaluate_backup_alerts
from app.services.psa_adapter import PSADispatcher
from app.core.limiter import limiter

router = APIRouter()

class RegisterCSRRequest(BaseModel):
    enrollment_code: str = Field(..., description="Mandantenspezifischer Enrollment-Code")
    hostname: str = Field(..., description="Eindeutiger Hostname des Endpunkts")
    os_info: str = Field(..., description="Betriebssystem-Metadaten")
    csr_pem: str = Field(..., description="Vom Agenten generiertes Certificate Signing Request im PEM-Format")

class RegisterCSRResponse(BaseModel):
    status: str
    client_certificate: str
    host_token: str

def verify_host_token(
    authorization: Optional[str] = Header(None),
    client_fingerprint: Optional[str] = Depends(get_client_certificate_fingerprint),
    db: Session = Depends(get_db),
) -> HostDevice:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Host-Bearer Token fehlt oder ungültig")
    
    token = authorization.split(" ")[1]
    host = db.query(HostDevice).filter(HostDevice.host_token == token).first()
    if not host or not host.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unbekanntes oder revokiertes Gerät")
    if settings.AEGIS_MTLS_ENABLED and (
        client_fingerprint is None
        or host.client_cert_fingerprint is None
        or not hmac.compare_digest(host.client_cert_fingerprint, client_fingerprint)
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Client-Zertifikat ist nicht an dieses Gerät gebunden")
    return host

@router.post("/agents/register", response_model=RegisterHostResponse)
@limiter.limit("30/minute")
def register_agent(
    request: Request,
    payload: RegisterHostRequest,
    client_fingerprint: Optional[str] = Depends(get_client_certificate_fingerprint),
    db: Session = Depends(get_db)
):
    if settings.AEGIS_MTLS_ENABLED and client_fingerprint is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Verifiziertes Client-Zertifikat erforderlich")
    tenant = db.query(Tenant).filter(Tenant.enrollment_code == payload.enrollment_code).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Ungültiger Enrollment-Code"
        )
    
    secure_host_token = f"ath_{secrets.token_hex(32)}"
    
    existing_host = db.query(HostDevice).filter(
        HostDevice.tenant_id == tenant.id,
        HostDevice.hostname == payload.hostname
    ).first()

    if existing_host:
        if not existing_host.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Gerät ist widerrufen und muss administrativ neu registriert werden")
        if (
            settings.AEGIS_MTLS_ENABLED
            and existing_host.client_cert_fingerprint is not None
            and not hmac.compare_digest(existing_host.client_cert_fingerprint, client_fingerprint or "")
        ):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Gerät ist bereits an ein anderes Client-Zertifikat gebunden")
        existing_host.host_token = secure_host_token
        existing_host.os_info = payload.os_info
        existing_host.client_cert_fingerprint = client_fingerprint
    else:
        new_host = HostDevice(
            tenant_id=tenant.id,
            hostname=payload.hostname,
            os_info=payload.os_info,
            host_token=secure_host_token,
            client_fingerprint=client_fingerprint,
        )
        db.add(new_host)

    db.commit()
    return RegisterHostResponse(status="success", host_token=secure_host_token)


@router.post("/agents/register/csr", response_model=RegisterCSRResponse)
@limiter.limit("20/minute")
def register_agent_with_csr(
    request: Request,
    payload: RegisterCSRRequest,
    db: Session = Depends(get_db)
):
    """
    Automatisierter mTLS-CSR-Enrollment-Endpoint. 
    Signiert ein vom Agenten eingereichtes Certificate Signing Request (CSR) über die interne CA,
    bindet den berechneten Zertifikatsfingerabdruck an das Host-Device und gibt ein kurzlebiges Zertifikat zurück.
    """
    tenant = db.query(Tenant).filter(Tenant.enrollment_code == payload.enrollment_code).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ungültiger Enrollment-Code"
        )
    
    # 1. Signierung des CSR über die interne PKI / CA der Control Plane
    try:
        client_cert_pem = sign_agent_csr_internally(
            csr_pem=payload.csr_pem,
            tenant_id=tenant.id,
            hostname=payload.hostname
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Fehler bei der internen CSR-Signierung: {str(e)}"
        )

    # 2. Extrahieren des Fingerabdrucks zur direkten Durchsetzung von mTLS bei Folgerequests
    cert_fingerprint = extract_fingerprint_from_cert_pem(client_cert_pem)
    secure_host_token = f"ath_{secrets.token_hex(32)}"

    existing_host = db.query(HostDevice).filter(
        HostDevice.tenant_id == tenant.id,
        HostDevice.hostname == payload.hostname
    ).first()

    if existing_host:
        if not existing_host.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="Gerät ist widerrufen und muss administrativ neu registriert werden"
            )
        existing_host.host_token = secure_host_token
        existing_host.os_info = payload.os_info
        existing_host.client_cert_fingerprint = cert_fingerprint
    else:
        new_host = HostDevice(
            tenant_id=tenant.id,
            hostname=payload.hostname,
            os_info=payload.os_info,
            host_token=secure_host_token,
            client_cert_fingerprint=cert_fingerprint,
            is_active=True
        )
        db.add(new_host)

    db.commit()
    return RegisterCSRResponse(
        status="success",
        client_certificate=client_cert_pem,
        host_token=secure_host_token
    )


@router.get("/agents/desired-state", response_model=Dict[str, bool])
def get_desired_state(
    host: HostDevice = Depends(verify_host_token),
    db: Session = Depends(get_db)
):
    modules = db.query(TenantModule).filter(TenantModule.tenant_id == host.tenant_id).all()
    state = {m.module_name: m.is_enabled for m in modules}
    return state


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

    previous_failed = False
    if payload.module_name != "backup_probe":
        previous_result = db.query(ModuleResult).filter(
            ModuleResult.tenant_id == host.tenant_id,
            ModuleResult.hostname == host.hostname,
            ModuleResult.module_name == payload.module_name,
        ).order_by(ModuleResult.timestamp.desc()).first()
        if previous_result:
            try:
                previous_findings = json.loads(previous_result.findings)
                previous_failed = any(
                    finding.get("status") == "FAIL" or finding.get("severity") in {"HIGH", "CRITICAL"}
                    for finding in previous_findings
                )
            except (TypeError, json.JSONDecodeError):
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

    if payload.module_name == "backup_probe":
        background_tasks.add_task(evaluate_backup_alerts, db)
    else:
        webhooks = db.query(WebhookConfig).filter(
            WebhookConfig.tenant_id == host.tenant_id,
            WebhookConfig.is_active.is_(True),
        ).all()
        alert_payload = payload.model_dump()
        alert_payload["tenant_id"] = host.tenant_id
        for webhook in webhooks:
            background_tasks.add_task(
                PSADispatcher.dispatch_event,
                url=webhook.url,
                secret_token=webhook.secret_token,
                payload=alert_payload,
                previous_state_failed=previous_failed,
                db=db,
                provider=webhook.provider,
                auth_header=webhook.auth_header,
                auth_value=webhook.auth_value,
            )

    return {"status": "success", "message": "Audit-Ergebnisse revisionssicher gespeichert."}
