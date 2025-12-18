# SENTRACARE-BE-AUTH/main.py
from datetime import datetime
import pytz
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import Base, engine, SessionLocal
from models import StatusEnum, User, RoleEnum
from schemas import AdminUpdateUserRequest, RegisterRequest, AdminCreateUserRequest, LoginRequest, UserResponse
from utils import hash_password, verify_password, create_access_token
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from utils import SECRET_KEY, ALGORITHM, AUDIENCE, ISSUER

bearer = HTTPBearer()

def require_role(roles: list[str]):
    def _dep(creds: HTTPAuthorizationCredentials = Depends(bearer)):
        token = creds.credentials
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], audience=AUDIENCE, issuer=ISSUER)
            role = payload.get("role")
            if role not in roles:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
            return payload
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return _dep

app = FastAPI(title="Sentracare Auth Service", description="API untuk autentikasi dan manajemen user di SentraCare", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://0.0.0.0:3000",
        "http://host.docker.internal:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Authorization", 
        "Content-Type",
        "Accept",
        "Origin",
        "X-Requested-With",
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Headers",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers"
        ],
)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post(
    "/auth/register", 
    response_model=UserResponse, 
    tags=["auth"], 
    summary="Register user baru", 
    description="Mendaftarkan user baru dengan role default Pasien. Validasi username, email, dan password."
    )
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    if data.password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Password dan konfirmasi tidak cocok")
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    user = User(
        full_name=data.full_name,
        username=data.username,
        email=data.email,
        phone_number=data.phone_number,
        password_hash=hash_password(data.password),
        address=data.address,
        role=RoleEnum.PASIEN,  # publik: hanya Pasien
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.post(
    "/auth/admin/create-user", 
    response_model=UserResponse, tags=["admin"],
    summary="Admin membuat user baru",
    description="Endpoint ini hanya dapat diakses oleh admin untuk membuat user baru dengan role yang ditentukan seperti Pasien/Dokter/SuperAdmin."
    )
def admin_create_user(
    data: AdminCreateUserRequest,
    db: Session = Depends(get_db),
    _claims: dict = Depends(require_role(["SuperAdmin"]))  # hanya admin
):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    # Role mapping ke Enum
    role_map = {
        "Pasien": RoleEnum.PASIEN,
        "Dokter": RoleEnum.DOKTER,
        "SuperAdmin": RoleEnum.SUPERADMIN,
    }
    user = User(
        full_name=data.full_name,
        username=data.username,
        email=data.email,
        phone_number= data.phone_number,
        password_hash=hash_password(data.password),
        role=role_map[data.role],
        status=StatusEnum.ACTIVE
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.get(
    "/auth/admin/users", 
    response_model=list[UserResponse], 
    tags=["admin"],
    description="Daftar semua user (SuperAdmin dan Dokter). Hanya dapat diakses oleh SuperAdmin."
    )
def list_users(skip: int = 0, limit: int = 20,db: Session = Depends(get_db), _claims: dict = Depends(require_role(["SuperAdmin"]))):
    return db.query(User).filter(User.role.in_([RoleEnum.SUPERADMIN, RoleEnum.DOKTER])).offset(skip).limit(limit).all()

@app.put(
    "/auth/admin/update-user/{user_id}", 
    response_model=UserResponse, 
    tags=["admin"],
    description="Update data user (full_name, username, email, status). Hanya dapat diakses oleh SuperAdmin."
    )
def update_user(user_id: int, data: AdminUpdateUserRequest, db: Session = Depends(get_db), _claims: dict = Depends(require_role(["SuperAdmin"]))):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.full_name = data.full_name
    user.username = data.username
    user.email = data.email
    user.status = data.status
    db.commit()
    db.refresh(user)
    return user

@app.post(
    "/auth/login", 
    tags=["auth"],
    summary="Login user",
    description="Login menggunakan username/email dan password. Mengembalikan JWT access token jika berhasil."
    )
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        (User.username == data.identifier) | (User.email == data.identifier)
    ).first()
    print("Login attempt:", data.identifier)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid password")
    wib = pytz.timezone("Asia/Jakarta")
    user.last_login = datetime.now(wib)
    db.commit()
    access_token = create_access_token(sub=user.username, role=user.role.value, email=user.email)
    print("User found:", user.username if user else "None")
    return {"access_token": access_token, "token_type": "bearer"}

@app.get(
    "/auth/me", 
    response_model=UserResponse, 
    tags=["auth"],
    summary="Ambil data user login",
    description="Mengembalikan data user berdasarkan JWT access token yang dikirim di header Authorization."
    )
def me(db: Session = Depends(get_db), claims: dict = Depends(require_role(["Pasien", "Dokter", "SuperAdmin"]))):
    username = claims.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


