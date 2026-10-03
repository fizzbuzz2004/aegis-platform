from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.config import settings
from . import sync, admin, dashboard, reporting

api_router = APIRouter()


def require_agent_mtls_transport(request: Request) -> None:
	if settings.AEGIS_MTLS_ENABLED and request.url.scheme != "https":
		raise HTTPException(
			status_code=status.HTTP_403_FORBIDDEN,
			detail="Agent API requires an mTLS-protected HTTPS connection",
		)


api_router.include_router(
	sync.router,
	tags=["Agent Sync Services"],
	dependencies=[Depends(require_agent_mtls_transport)],
)
api_router.include_router(admin.router, tags=["Admin & Control Services"])
api_router.include_router(dashboard.router, tags=["Dashboard UI"])
api_router.include_router(reporting.router, tags=["Compliance Reporting"])
