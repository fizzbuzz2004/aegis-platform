from fastapi import APIRouter

from . import sync, admin, dashboard, reporting

api_router = APIRouter()
api_router.include_router(sync.router, tags=["Agent Sync Services"])
api_router.include_router(admin.router, tags=["Admin & Control Services"])
api_router.include_router(dashboard.router, tags=["Dashboard UI"])
api_router.include_router(reporting.router, tags=["Compliance Reporting"])
