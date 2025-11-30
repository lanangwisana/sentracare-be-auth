# SENTRACARE-BE-AUTH/main.py
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import Base, engine, SessionLocal
from models import User, RoleEnum
from schemas import RegisterRequest, LoginRequest, UserResponse
from utils import hash_password, verify_password, create_access_token

app = FastAPI(title="Sentracare Auth Service")

# CORS (adjust origins for your frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables
Base.metadata.create_all(bind=engine)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/auth/register", response_model=UserResponse, tags=["auth"])
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    # Check uniqueness
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    user = User(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        role=RoleEnum.PASIEN,  # enforce PASIEN for public registration
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.post("/auth/login", tags=["auth"])
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if user.role != RoleEnum.PASIEN:
        raise HTTPException(status_code=403, detail="Only pasien can login here")

    access_token = create_access_token(sub=user.username, role=user.role.value)
    return {"access_token": access_token, "token_type": "bearer"}
