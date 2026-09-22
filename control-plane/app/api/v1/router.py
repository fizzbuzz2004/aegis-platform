from fastapi import APIRouter

# Relativer Import (da sync.py und admin.py im selben Ordner v1 liegen)
from . import sync, admin

# Alternativ als absoluter Import:
# from app.api.v1 import sync, admin

api_router = APIRouter()
api_router.include_router(sync.router, tags=["Agent Sync Services"])
api_router.include_router(admin.router, tags=["Admin & Control Services"])
