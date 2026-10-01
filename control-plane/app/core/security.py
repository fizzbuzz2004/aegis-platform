from datetime import datetime, timedelta, timezone
from typing import Optional, List
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.orm import User, UserRole

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Ungültige Authentifizierungsdaten (JWT)",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if user is None:
        raise credentials_exception
    if user.role == UserRole.CUSTOMER_ADMIN and user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Customer-Admin-Konto ist keinem Mandanten zugeordnet.",
        )
    return user

def require_role(required_roles: List[UserRole]):
    """Closure Dependency zur sauberen Rollenvalidierung auf Endpunkten"""
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unzureichende Berechtigungen für diese Aktion."
            )
        return current_user
    return role_checker

def assert_tenant_access(user: User, tenant_id: int) -> None:
    if user.role == UserRole.CUSTOMER_ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Kein Zugriff auf diesen Mandanten.",
        )


get_current_admin_user = require_role([UserRole.ADMIN, UserRole.TECHNICIAN])
get_current_tenant_user = require_role([
    UserRole.ADMIN,
    UserRole.TECHNICIAN,
    UserRole.CUSTOMER_ADMIN,
])
get_any_active_user = require_role([
    UserRole.ADMIN,
    UserRole.TECHNICIAN,
    UserRole.JUNIOR,
    UserRole.CUSTOMER_ADMIN,
])
