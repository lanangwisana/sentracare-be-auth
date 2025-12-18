# SENTRACARE-BE-AUTH/models.py
from sqlalchemy import Column, Integer, String, DateTime, Enum
from datetime import datetime
import pytz
from database import Base
import enum

class StatusEnum(str, enum.Enum):
    ACTIVE = "Active"
    INACTIVE = "Inactive"

class RoleEnum(str, enum.Enum):
    PASIEN = "Pasien"
    DOKTER = "Dokter"
    SUPERADMIN = "SuperAdmin"

def now_wib():
    return datetime.now(pytz.timezone("Asia/Jakarta"))

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(100), nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    phone_number = Column(String(20), index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(RoleEnum), nullable=False, default=RoleEnum.PASIEN)
    status = Column(Enum(StatusEnum), nullable=False, default=StatusEnum.ACTIVE)
    last_login = Column(DateTime, nullable=True)
    address = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=now_wib, nullable=False)
    updated_at = Column(DateTime, default=now_wib, onupdate=now_wib, nullable=False)