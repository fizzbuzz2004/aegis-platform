from pydantic import BaseModel
from typing import List, Optional

class FindingItem(BaseModel):
    status: str
    code: str
    severity: str
    message: str
    compliance: Optional[List[str]] = []

class ResultPayload(BaseModel):
    hostname: str
    module_name: str
    findings: List[FindingItem]

class ToggleRequest(BaseModel):
    tenant_id: int
    module_name: str
    enable: bool

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class RegisterHostRequest(BaseModel):
    enrollment_code: str
    hostname: str
    os_info: str

class RegisterHostResponse(BaseModel):
    status: str
    host_token: str
