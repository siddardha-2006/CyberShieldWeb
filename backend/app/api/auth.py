from fastapi import APIRouter, HTTPException, Depends
from app.schemas.auth import UserRegisterRequest, UserLoginRequest, TokenResponse, UserProfile
from app.core.security import get_password_hash, verify_password, create_access_token
from app.database.repositories.users import UserRepository

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse)
async def register(req: UserRegisterRequest):
    existing = await UserRepository.get_by_username_or_email(req.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    existing_email = await UserRepository.get_by_username_or_email(req.email)
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed = get_password_hash(req.password)
    user_doc = {
        "username": req.username,
        "email": req.email,
        "password_hash": hashed
    }
    user = await UserRepository.create_user(user_doc)
    token = create_access_token(user["id"])
    return TokenResponse(
        access_token=token,
        username=user["username"],
        email=user["email"]
    )


@router.post("/login", response_model=TokenResponse)
async def login(req: UserLoginRequest):
    user = await UserRepository.get_by_username_or_email(req.username_or_email)
    if not user or not verify_password(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token(user["id"])
    return TokenResponse(
        access_token=token,
        username=user["username"],
        email=user["email"]
    )


@router.get("/me")
async def get_me():
    return {"message": "Authenticated user profile endpoint"}

