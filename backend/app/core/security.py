import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Any, Union
from jose import jwt
from passlib.context import CryptContext
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    # Use sha256 fallback if bcrypt has platform issues
    try:
        return pwd_context.hash(password)
    except Exception:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return hashlib.sha256(plain_password.encode("utf-8")).hexdigest() == hashed_password


def create_access_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def generate_hmac_identifier(value: str) -> str:
    """
    Generate HMAC-SHA-256 privacy identifier for normalized indicators.
    Avoids storing low-entropy raw indicators directly in database.
    """
    secret = settings.CYBER_SHIELD_HMAC_SECRET.encode("utf-8")
    normalized_val = value.strip().lower().encode("utf-8")
    return hmac.new(secret, normalized_val, hashlib.sha256).hexdigest()

