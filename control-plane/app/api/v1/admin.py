from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import json

from app.core.database import get_db
from app.core.security import verify_password, create_access_token, get_current_admin_user
from app.models.orm import User, TenantModule, ModuleResult, Tenant
from app.models.module_state import ToggleRequest, TokenResponse

router = APIRouter()

@router.post("/auth/login", response_model=TokenResponse)
def admin_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ungültiger Username oder Passwort")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/admin/toggle")
def toggle_module(
    req: ToggleRequest, 
    current_user: User = Depends(get_current_admin_user), 
    db: Session = Depends(get_db)
):
    module_entry = db.query(TenantModule).filter(
        TenantModule.tenant_id == req.tenant_id,
        TenantModule.module_name == req.module_name
    ).first()

    if not module_entry:
        module_entry = TenantModule(tenant_id=req.tenant_id, module_name=req.module_name, is_enabled=req.enable)
        db.add(module_entry)
    else:
        module_entry.is_enabled = req.enable

    db.commit()
    return {"status": "success", "tenant_id": req.tenant_id, "module": req.module_name, "enabled": req.enable}

@router.get("/admin/results/{tenant_id}")
def get_tenant_results(
    tenant_id: int, 
    current_user: User = Depends(get_current_admin_user), 
    db: Session = Depends(get_db)
):
    # Strict Multi-Tenancy Scoping
    results = db.query(ModuleResult).filter(ModuleResult.tenant_id == tenant_id).order_by(ModuleResult.timestamp.desc()).all()
    output = []
    for r in results:
        try:
            parsed_findings = json.loads(r.findings)
        except Exception:
            parsed_findings = []
        output.append({
            "id": r.id,
            "hostname": r.hostname,
            "module_name": r.module_name,
            "timestamp": r.timestamp.isoformat(),
            "findings": parsed_findings
        })
    return {"status": "success", "tenant_id": tenant_id, "results": output}
