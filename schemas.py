# SENTRACARE-BE-AUTH/schemas.py
from pydantic import BaseModel, EmailStr
from typing import Literal

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

class AdminCreateUserRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Literal["Pasien", "Dokter", "SuperAdmin"]

class LoginRequest(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: Literal["Pasien", "Dokter", "SuperAdmin"]

    class Config:
        from_attributes = True 
