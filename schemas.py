# SENTRACARE-BE-AUTH/schemas.py
from datetime import datetime
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
    full_name: str
    username: str
    email: EmailStr
    phone_number: str
    password: str
    role: Literal["Pasien", "Dokter", "SuperAdmin"]
    status: Literal["Active", "Inactive"] = "Active"

class AdminUpdateUserRequest(BaseModel):
    full_name: str
    username: str
    email: EmailStr
    status: Literal["Active", "Inactive"]

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
    status: Literal["Active", "Inactive"]
    last_login: datetime | None = None
    created_at: datetime
    updated_at: datetime


    class Config:
        from_attributes = True 
