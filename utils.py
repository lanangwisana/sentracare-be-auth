# SENTRACARE-BE-AUTH/utils.py
# utils.py
import os
import uuid
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "change-this-secret-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
ISSUER = os.getenv("AUTH_ISSUER", "sentracare-auth")
AUDIENCE = os.getenv("AUTH_AUDIENCE", "sentracare-services")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(sub: str, email: str, role: str) -> str:
    now = datetime.utcnow()
    to_encode = {
        "sub": sub,
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "jti": str(uuid.uuid4()),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "version": 1,
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
