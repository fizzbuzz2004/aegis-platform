from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional
import json

from app.core.database import get_db
from app.models.orm import Tenant, TenantModule, ModuleResult
from app.models.module_state import ResultPayload

router = APIRouter()

def verify_tenant_token(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> Tenant:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer Token fehlt oder ungültig")
    token = authorization.split(" ")[1]
    tenant = db.query(Tenant).filter(Tenant.api_token == token).first()
    if not tenant:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unautorisierter Agent-Zugriff")
    return tenant

@router.get("/sync")
def sync_config(
    hostname: Optional[str] = None, 
    os: Optional[str] = None, 
    tenant: Tenant = Depends(verify_tenant_token),
    db: Session = Depends(get_db)
):
    modules_query = db.query(TenantModule).filter(TenantModule.tenant_id == tenant.id).all()
    modules_map = {m.module_name: m.is_enabled for m in modules_query}
    return {
        "status": "ok",
        "tenant_id": tenant.id,
        "tenant_name": tenant.name,
        "modules": modules_map
    }

@router.post("/results")
def submit_results(
    payload: ResultPayload, 
    tenant: Tenant = Depends(verify_tenant_token),
    db: Session = Depends(get_db)
):
    findings_json = json.dumps([f.model_dump() for f in payload.findings])
    result_entry = ModuleResult(
        tenant_id=tenant.id,
        hostname=payload.hostname,
        module_name=payload.module_name,
        findings=findings_json
    )
    db.add(result_entry)
    db.commit()
    return {"status": "success", "message": "Ergebnisse sicher gespeichert"}
