from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import jwt
import bcrypt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="ZTNA Security System", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
MFA_EXPIRY_MINUTES = 10

# Email configuration (using environment variables)
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: EmailStr
    password_hash: str
    role: str = "user"  # user, admin, guest
    is_active: bool = True
    mfa_enabled: bool = True
    mfa_secret: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    account_locked_until: Optional[datetime] = None

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class MFAVerify(BaseModel):
    username: str
    mfa_code: str

class Application(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    url: str
    icon_url: Optional[str] = None
    category: str = "general"
    is_active: bool = True
    requires_mfa: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ApplicationCreate(BaseModel):
    name: str
    description: str
    url: str
    icon_url: Optional[str] = None
    category: str = "general"
    requires_mfa: bool = False

class AccessPolicy(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    user_roles: List[str] = []
    applications: List[str] = []  # application IDs
    time_restrictions: Optional[Dict[str, Any]] = None  # {"start": "09:00", "end": "17:00", "days": ["monday", "tuesday"]}
    location_restrictions: Optional[List[str]] = None  # IP ranges or countries
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AccessPolicyCreate(BaseModel):
    name: str
    description: str
    user_roles: List[str] = []
    applications: List[str] = []
    time_restrictions: Optional[Dict[str, Any]] = None
    location_restrictions: Optional[List[str]] = None

class AccessLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    username: str
    application_id: str
    application_name: str
    action: str  # "login", "access_granted", "access_denied", "logout"
    ip_address: str
    user_agent: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    success: bool
    reason: Optional[str] = None

class MFASession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    mfa_code: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    verified: bool = False

# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def create_jwt_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def generate_mfa_code() -> str:
    return str(secrets.randbelow(1000000)).zfill(6)

async def send_mfa_email(email: str, mfa_code: str):
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        print(f"MFA Code for {email}: {mfa_code}")  # For testing without email
        return
    
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = email
        msg['Subject'] = "ZTNA Security - MFA Code"
        
        body = f"""
        Your MFA verification code is: {mfa_code}
        
        This code will expire in {MFA_EXPIRY_MINUTES} minutes.
        
        If you didn't request this code, please contact your administrator.
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"Failed to send MFA email: {e}")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_jwt_token(credentials.credentials)
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"username": username})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return User(**user)

async def get_admin_user(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

async def log_access_attempt(user_id: str, username: str, application_id: str, 
                           application_name: str, action: str, ip_address: str, 
                           user_agent: str, success: bool, reason: str = None):
    log_entry = AccessLog(
        user_id=user_id,
        username=username,
        application_id=application_id,
        application_name=application_name,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success,
        reason=reason
    )
    await db.access_logs.insert_one(log_entry.dict())

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def is_time_allowed(time_restrictions: Dict[str, Any]) -> bool:
    if not time_restrictions:
        return True
    
    now = datetime.now()
    current_day = now.strftime("%A").lower()
    current_time = now.strftime("%H:%M")
    
    allowed_days = time_restrictions.get("days", [])
    if allowed_days and current_day not in [day.lower() for day in allowed_days]:
        return False
    
    start_time = time_restrictions.get("start")
    end_time = time_restrictions.get("end")
    
    if start_time and end_time:
        if start_time <= current_time <= end_time:
            return True
        return False
    
    return True

# Authentication endpoints
@api_router.post("/auth/register")
async def register_user(user_data: UserCreate):
    # Check if username or email already exists
    existing_user = await db.users.find_one({
        "$or": [{"username": user_data.username}, {"email": user_data.email}]
    })
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    # Hash password
    password_hash = hash_password(user_data.password)
    
    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=password_hash,
        role=user_data.role
    )
    
    await db.users.insert_one(user.dict())
    return {"message": "User registered successfully", "user_id": user.id}

@api_router.post("/auth/login")
async def login_user(login_data: UserLogin, request: Request):
    user = await db.users.find_one({"username": login_data.username})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user_obj = User(**user)
    
    # Check if account is locked
    if user_obj.account_locked_until:
        # Ensure both datetimes are timezone-aware for comparison
        locked_until = user_obj.account_locked_until
        if not locked_until.tzinfo:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > datetime.now(timezone.utc):
            raise HTTPException(status_code=423, detail="Account is temporarily locked")
    
    # Verify password
    if not verify_password(login_data.password, user_obj.password_hash):
        # Increment failed attempts
        await db.users.update_one(
            {"username": login_data.username},
            {"$inc": {"failed_login_attempts": 1}}
        )
        
        # Lock account after 5 failed attempts
        if user_obj.failed_login_attempts >= 4:
            lock_until = datetime.now(timezone.utc) + timedelta(minutes=30)
            await db.users.update_one(
                {"username": login_data.username},
                {"$set": {"account_locked_until": lock_until}}
            )
        
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Reset failed attempts on successful password verification
    await db.users.update_one(
        {"username": login_data.username},
        {"$set": {"failed_login_attempts": 0, "account_locked_until": None}}
    )
    
    # Generate and send MFA code
    mfa_code = generate_mfa_code()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=MFA_EXPIRY_MINUTES)
    
    mfa_session = MFASession(
        username=login_data.username,
        mfa_code=mfa_code,
        expires_at=expires_at
    )
    
    await db.mfa_sessions.insert_one(mfa_session.dict())
    await send_mfa_email(user_obj.email, mfa_code)
    
    # Log login attempt
    await log_access_attempt(
        user_obj.id, user_obj.username, "system", "login", "mfa_sent",
        get_client_ip(request), str(request.headers.get("user-agent", "")),
        True, "MFA code sent"
    )
    
    return {"message": "MFA code sent to your email", "requires_mfa": True}

@api_router.post("/auth/verify-mfa")
async def verify_mfa(mfa_data: MFAVerify, request: Request):
    # Find active MFA session
    mfa_session = await db.mfa_sessions.find_one({
        "username": mfa_data.username,
        "mfa_code": mfa_data.mfa_code,
        "verified": False,
        "expires_at": {"$gt": datetime.now(timezone.utc)}
    })
    
    if not mfa_session:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA code")
    
    # Mark MFA session as verified
    await db.mfa_sessions.update_one(
        {"id": mfa_session["id"]},
        {"$set": {"verified": True}}
    )
    
    # Get user
    user = await db.users.find_one({"username": mfa_data.username})
    user_obj = User(**user)
    
    # Update last login
    await db.users.update_one(
        {"username": mfa_data.username},
        {"$set": {"last_login": datetime.now(timezone.utc)}}
    )
    
    # Create JWT token
    token_data = {"sub": user_obj.username, "role": user_obj.role}
    access_token = create_jwt_token(token_data)
    
    # Log successful login
    await log_access_attempt(
        user_obj.id, user_obj.username, "system", "login", "login_success",
        get_client_ip(request), str(request.headers.get("user-agent", "")),
        True, "MFA verified successfully"
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user_obj.id,
            "username": user_obj.username,
            "email": user_obj.email,
            "role": user_obj.role
        }
    }

@api_router.get("/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "last_login": current_user.last_login
    }

# Application management endpoints
@api_router.post("/admin/applications", response_model=Application)
async def create_application(app_data: ApplicationCreate, admin_user: User = Depends(get_admin_user)):
    application = Application(**app_data.dict())
    await db.applications.insert_one(application.dict())
    return application

@api_router.get("/admin/applications", response_model=List[Application])
async def get_all_applications(admin_user: User = Depends(get_admin_user)):
    applications = await db.applications.find().to_list(1000)
    return [Application(**app) for app in applications]

@api_router.get("/applications", response_model=List[Application])
async def get_user_applications(current_user: User = Depends(get_current_user)):
    # Get user's accessible applications based on policies
    policies = await db.access_policies.find({
        "user_roles": current_user.role,
        "is_active": True
    }).to_list(1000)
    
    allowed_app_ids = set()
    for policy in policies:
        policy_obj = AccessPolicy(**policy)
        
        # Check time restrictions
        if not is_time_allowed(policy_obj.time_restrictions):
            continue
            
        allowed_app_ids.update(policy_obj.applications)
    
    if not allowed_app_ids:
        return []
    
    applications = await db.applications.find({
        "id": {"$in": list(allowed_app_ids)},
        "is_active": True
    }).to_list(1000)
    
    return [Application(**app) for app in applications]

@api_router.post("/applications/{app_id}/access")
async def access_application(app_id: str, request: Request, current_user: User = Depends(get_current_user)):
    # Get application
    app = await db.applications.find_one({"id": app_id, "is_active": True})
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    app_obj = Application(**app)
    
    # Check if user has access based on policies
    policies = await db.access_policies.find({
        "user_roles": current_user.role,
        "applications": app_id,
        "is_active": True
    }).to_list(1000)
    
    access_granted = False
    denial_reason = "No matching access policy"
    
    for policy in policies:
        policy_obj = AccessPolicy(**policy)
        
        # Check time restrictions
        if not is_time_allowed(policy_obj.time_restrictions):
            denial_reason = "Access not allowed at this time"
            continue
        
        # If we reach here, access is granted
        access_granted = True
        denial_reason = None
        break
    
    # Log access attempt
    await log_access_attempt(
        current_user.id, current_user.username, app_id, app_obj.name,
        "access_attempt", get_client_ip(request), 
        str(request.headers.get("user-agent", "")),
        access_granted, denial_reason
    )
    
    if not access_granted:
        raise HTTPException(status_code=403, detail=denial_reason)
    
    return {
        "message": "Access granted",
        "application": app_obj.dict(),
        "redirect_url": app_obj.url,
        "access_token": create_jwt_token({"sub": current_user.username, "app": app_id}, 
                                       timedelta(hours=1))
    }

# Policy management endpoints
@api_router.post("/admin/policies", response_model=AccessPolicy)
async def create_access_policy(policy_data: AccessPolicyCreate, admin_user: User = Depends(get_admin_user)):
    policy = AccessPolicy(**policy_data.dict())
    await db.access_policies.insert_one(policy.dict())
    return policy

@api_router.get("/admin/policies", response_model=List[AccessPolicy])
async def get_access_policies(admin_user: User = Depends(get_admin_user)):
    policies = await db.access_policies.find().to_list(1000)
    return [AccessPolicy(**policy) for policy in policies]

@api_router.put("/admin/policies/{policy_id}")
async def update_access_policy(policy_id: str, policy_data: AccessPolicyCreate, 
                              admin_user: User = Depends(get_admin_user)):
    result = await db.access_policies.update_one(
        {"id": policy_id},
        {"$set": policy_data.dict()}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"message": "Policy updated successfully"}

@api_router.delete("/admin/policies/{policy_id}")
async def delete_access_policy(policy_id: str, admin_user: User = Depends(get_admin_user)):
    result = await db.access_policies.delete_one({"id": policy_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"message": "Policy deleted successfully"}

# User management endpoints
@api_router.get("/admin/users", response_model=List[Dict])
async def get_all_users(admin_user: User = Depends(get_admin_user)):
    users = await db.users.find().to_list(1000)
    return [{
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "is_active": user["is_active"],
        "created_at": user["created_at"],
        "last_login": user.get("last_login"),
        "failed_login_attempts": user.get("failed_login_attempts", 0)
    } for user in users]

@api_router.put("/admin/users/{user_id}/role")
async def update_user_role(user_id: str, role_data: dict, admin_user: User = Depends(get_admin_user)):
    if role_data.get("role") not in ["user", "admin", "guest"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    result = await db.users.update_one(
        {"id": user_id},
        {"$set": {"role": role_data["role"]}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User role updated successfully"}

# Access logs endpoints
@api_router.get("/admin/logs", response_model=List[AccessLog])
async def get_access_logs(admin_user: User = Depends(get_admin_user), limit: int = 100):
    logs = await db.access_logs.find().sort("timestamp", -1).limit(limit).to_list(limit)
    return [AccessLog(**log) for log in logs]

@api_router.get("/logs/my")
async def get_user_logs(current_user: User = Depends(get_current_user), limit: int = 50):
    logs = await db.access_logs.find({"user_id": current_user.id}).sort("timestamp", -1).limit(limit).to_list(limit)
    return [AccessLog(**log) for log in logs]

# Dashboard stats
@api_router.get("/admin/stats")
async def get_dashboard_stats(admin_user: User = Depends(get_admin_user)):
    total_users = await db.users.count_documents({})
    active_users = await db.users.count_documents({"is_active": True})
    total_apps = await db.applications.count_documents({})
    active_apps = await db.applications.count_documents({"is_active": True})
    total_policies = await db.access_policies.count_documents({})
    
    # Recent access attempts
    recent_logs = await db.access_logs.find().sort("timestamp", -1).limit(10).to_list(10)
    
    return {
        "total_users": total_users,
        "active_users": active_users,
        "total_applications": total_apps,
        "active_applications": active_apps,
        "total_policies": total_policies,
        "recent_access_attempts": [AccessLog(**log).dict() for log in recent_logs]
    }

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Create admin user on startup
@app.on_event("startup")
async def create_admin_user():
    admin_exists = await db.users.find_one({"role": "admin"})
    if not admin_exists:
        admin_user = User(
            username="admin",
            email="admin@example.com",
            password_hash=hash_password("admin123"),
            role="admin"
        )
        await db.users.insert_one(admin_user.dict())
        logger.info("Default admin user created: admin/admin123")