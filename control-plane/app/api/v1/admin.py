import secrets
from typing import List, Optional
import pyotp
from fastapi import APIRouter, Depends, Form, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import create_access_token, get_current_admin_user, verify_password
from app.models.module_state import ToggleRequest, TokenResponse
from app.models.orm import ModuleResult, Tenant, TenantModule, User

router = APIRouter()


class TenantCreateSchema(BaseModel):
    name: str
    psa_company_id: Optional[str] = None
    psa_site_id: Optional[str] = None


class TenantResponseSchema(BaseModel):
    id: int
    name: str
    enrollment_code: str
    psa_company_id: Optional[str] = None


@router.post("/auth/login", response_model=TokenResponse)
def admin_login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    mfa_code: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Ungültiger Username oder Passwort",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Benutzerkonto ist deaktiviert",
        )

    # Multi-Faktor-Authentifizierung (MFA) Check
    if user.mfa_enabled:
        if not mfa_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA-Code erforderlich",
            )
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(mfa_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Ungültiger MFA-Code",
            )

    role_value = user.role.value if hasattr(user.role, "value") else str(user.role)
    access_token = create_access_token(data={"sub": user.username, "role": role_value})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/admin/tenants", response_model=TenantResponseSchema)
def create_tenant(
    payload: TenantCreateSchema,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    enrollment_code = f"enc_{secrets.token_hex(16)}"
    tenant = Tenant(
        name=payload.name,
        enrollment_code=enrollment_code,
        psa_company_id=payload.psa_company_id,
        psa_site_id=payload.psa_site_id,
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)

    # Standardmodule aktivieren
    default_modules = ["cis_hardening", "backup_probe", "security_probe", "storage_probe"]
    for mod in default_modules:
        db.add(TenantModule(tenant_id=tenant.id, module_name=mod, is_enabled=True))
    db.commit()

    return tenant


@router.get("/admin/tenants", response_model=List[TenantResponseSchema])
def list_tenants(
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    return db.query(Tenant).all()


@router.post("/admin/tenants/batch")
def batch_onboard_tenants(
    tenant_names: List[str],
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    created = []
    for name in tenant_names:
        code = f"enc_{secrets.token_hex(16)}"
        t = Tenant(name=name, enrollment_code=code)
        db.add(t)
        db.flush()
        for mod in ["cis_hardening", "security_probe"]:
            db.add(TenantModule(tenant_id=t.id, module_name=mod, is_enabled=True))
        created.append({"name": name, "enrollment_code": code})
    db.commit()
    return {"status": "success", "tenants": created}


@router.post("/admin/toggle")
def toggle_module(
    req: ToggleRequest,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    module_entry = (
        db.query(TenantModule)
        .filter(
            TenantModule.tenant_id == req.tenant_id,
            TenantModule.module_name == req.module_name,
        )
        .first()
    )

    if not module_entry:
        module_entry = TenantModule(
            tenant_id=req.tenant_id,
            module_name=req.module_name,
            is_enabled=req.enable,
        )
        db.add(module_entry)
    else:
        module_entry.is_enabled = req.enable

    db.commit()
    return {
        "status": "success",
        "tenant_id": req.tenant_id,
        "module": req.module_name,
        "enabled": req.enable,
    }
