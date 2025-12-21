import os
import uuid
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import jwt

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "sentracare-rahasia-sangat-aman-123" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
ISSUER = "sentracare-auth"
AUDIENCE = "sentracare-services"

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(sub: str, email: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    to_encode = {
        "sub": sub,
        "email": email,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "jti": str(uuid.uuid4()),
        "iss": ISSUER,
        "aud": AUDIENCE,
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)