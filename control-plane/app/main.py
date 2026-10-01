import logging
import secrets
import sys
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.core.modules import DEFAULT_TENANT_MODULES
from app.core.security import get_password_hash, verify_password
from app.core.limiter import limiter  # Zentraler Import zur Vermeidung zirkulärer Imports
from app.models.orm import User, Tenant, TenantModule
from app.api.v1.router import api_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def seed_initial_data():
    db = SessionLocal()
    try:
        initial_pw = settings.ADMIN_INITIAL_PASSWORD

        # Bootstrap credentials must be usable after restarts with a persistent DB.
        if not initial_pw or len(initial_pw) < 12:
            logger.error("KRITISCH: 'ADMIN_INITIAL_PASSWORD' nicht gesetzt oder zu kurz (< 12).")
            sys.exit(1)

        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                hashed_password=get_password_hash(initial_pw),
                is_active=True,
                must_change_password=True,
            )
            db.add(admin_user)
        elif admin_user.must_change_password:
            try:
                password_matches = verify_password(initial_pw, admin_user.hashed_password)
            except (TypeError, ValueError):
                password_matches = False
            if not password_matches:
                admin_user.hashed_password = get_password_hash(initial_pw)
        
        pilot_tenant = db.query(Tenant).filter(Tenant.id == 1).first()
        if not pilot_tenant:
            pilot_tenant = Tenant(id=1, name="Pilot-Systemhaus-Meier", enrollment_code="enroll_pilot_2026")
            db.add(pilot_tenant)
            db.flush()

        existing_modules = {
            module.module_name
            for module in db.query(TenantModule).filter(TenantModule.tenant_id == pilot_tenant.id).all()
        }
        db.add_all([
            TenantModule(tenant_id=pilot_tenant.id, module_name=module_name, is_enabled=True)
            for module_name in DEFAULT_TENANT_MODULES
            if module_name not in existing_modules
        ])

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Hinweis: In Produktion idealerweise auf spezifische Domains eingrenzen
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
    # NIS2/ISO27001: Verhinderung von XSS und Injection in Dashboards
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:;"
    )
    return response

app.include_router(api_router, prefix="/api/v1")
