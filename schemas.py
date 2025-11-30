# SENTRACARE-BE-AUTH/schemas.py
from pydantic import BaseModel, EmailStr
from typing import Literal

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: Literal["Pasien", "SuperAdmin"]

    class Config:
        from_attributes = True  # pydantic v2 equivalent to orm_mode
