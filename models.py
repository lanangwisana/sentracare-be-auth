# SENTRACARE-BE-AUTH/models.py
from sqlalchemy import Column, Integer, String, DateTime, Enum
from datetime import datetime
from database import Base
import enum

class RoleEnum(str, enum.Enum):
    PASIEN = "Pasien"
    DOKTER = "Dokter"
    ADMIN = "SuperAdmin"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(RoleEnum), nullable=False, default=RoleEnum.PASIEN)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
