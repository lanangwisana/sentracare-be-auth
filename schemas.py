# SENTRACARE-BE-AUTH/schemas.py
from pydantic import BaseModel, EmailStr
from typing import Literal

class RegisterRequest(BaseModel):
    full_name: str
    username: str
    email: EmailStr
    phone_number: str
    password: str
    confirm_password: str
    address: str | None = None

class AdminCreateUserRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Literal["Pasien", "Dokter", "SuperAdmin"]

class LoginRequest(BaseModel):
    identifier: str
    password: str

class UserResponse(BaseModel):
    id: int
    full_name: str
    username: str
    email: EmailStr
    phone_number: str
    address: str | None = None
    role: Literal["Pasien", "Dokter", "SuperAdmin"]

    class Config:
        from_attributes = True 
