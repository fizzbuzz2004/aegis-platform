from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class TenantBase(BaseModel):
    name: str

class TenantCreate(TenantBase):
    api_token: str

class TenantResponse(TenantBase):
    id: int
    api_token: str
    created_at: datetime

    class Config:
        from_attributes = True
