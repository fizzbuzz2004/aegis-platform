from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.core.security import get_password_hash
from app.models.orm import User, Tenant, TenantModule
from app.api.v1.router import api_router

limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

def seed_initial_data():
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == "admin").first():
            admin_user = User(username="admin", hashed_password=get_password_hash("admin123"), is_active=True)
            db.add(admin_user)
        
        if not db.query(Tenant).filter(Tenant.id == 1).first():
            pilot_tenant = Tenant(id=1, name="Pilot-Systemhaus-Meier", api_token="aegis_test_token_001")
            db.add(pilot_tenant)
            db.commit()

            mod1 = TenantModule(tenant_id=1, module_name="cis_hardening", is_enabled=True)
            mod2 = TenantModule(tenant_id=1, module_name="backup_probe", is_enabled=False)
            db.add_all([mod1, mod2])

        db.commit()
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    seed_initial_data()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME, 
    version=settings.VERSION,
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS & Security Hardening
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

app.include_router(api_router, prefix="/api/v1")
