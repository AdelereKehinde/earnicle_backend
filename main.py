"""
main.py — Earnicle API.

Auth: custom JWT (access + refresh), email OTP for signup/reset (Supabase Auth
is NOT used — Supabase is the Postgres host only).
RBAC: 'reader' | 'writer' | 'both' gates on write endpoints.
Idempotency: Idempotency-Key header required on payment/withdrawal writes.
Pagination: cursor-based (created_at,id) on every list endpoint.
"""
import os
import base64
import json
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional, List
from uuid import UUID

import httpx
from fastapi import FastAPI, Depends, HTTPException, status, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import select, func as sqlfunc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from dotenv import load_dotenv

import models
import schemas
from database import get_db, engine, Base

load_dotenv()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30
OTP_EXPIRE_MINUTES = 10
OTP_MAX_ATTEMPTS = 5

PAYSTACK_SECRET_KEY = os.environ["PAYSTACK_SECRET_KEY"]  # server-only, never exposed
PAYSTACK_BASE_URL = "https://api.paystack.co"

CLOUDINARY_API_KEY = os.environ["CLOUDINARY_API_KEY"]
CLOUDINARY_API_SECRET = os.environ["CLOUDINARY_API_SECRET"]  # server-only
CLOUDINARY_CLOUD_NAME = os.environ["CLOUDINARY_CLOUD_NAME"]
CLOUDINARY_UPLOAD_PRESET = os.environ.get("CLOUDINARY_UPLOAD_PRESET", "earnicle_avatars")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Earnicle API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    # Dev convenience only — use Alembic migrations in production instead.
    if os.environ.get("AUTO_CREATE_TABLES") == "1":
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_token(sub: str, expires_delta: timedelta, token_type: str) -> str:
    payload = {
        "sub": sub,
        "type": token_type,
        "exp": datetime.now(timezone.utc) + expires_delta,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_token_pair(user_id: str) -> schemas.TokenResponse:
    access = create_token(user_id, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES), "access")
    refresh = create_token(user_id, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS), "refresh")
    return schemas.TokenResponse(access_token=access, refresh_token=refresh)


async def get_current_user(
    authorization: str = Header(...),
    db: AsyncSession = Depends(get_db),
) -> models.Profile:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong token type")
        user_id = payload["sub"]
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")

    result = await db.execute(select(models.Profile).where(models.Profile.id == UUID(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user


def require_role(*allowed_roles: models.RoleEnum):
    """RBAC dependency — gates write-side endpoints by profile role.
    'writer' and 'both' can publish content; pure 'reader' cannot."""
    async def _check(user: models.Profile = Depends(get_current_user)) -> models.Profile:
        if user.role not in allowed_roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"This action requires role: {', '.join(r.value for r in allowed_roles)}",
            )
        return user
    return _check


require_writer = require_role(models.RoleEnum.writer, models.RoleEnum.both)


# ---------------------------------------------------------------------------
# OTP helpers
# ---------------------------------------------------------------------------

def generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


async def send_otp_email(email: str, code: str, purpose: str):
    """Plug in your transactional email provider here (Resend, SES, Postmark...).
    Left as an explicit hook rather than guessed at, since no provider was
    specified — wire this up before going live."""
    # e.g. await resend_client.send(to=email, subject=..., html=...)
    print(f"[dev] OTP for {email} ({purpose}): {code}")


async def issue_otp(db: AsyncSession, email: str, purpose: str) -> str:
    code = generate_otp()
    otp = models.OTPCode(
        email=email,
        code_hash=hash_password(code),
        purpose=purpose,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES),
    )
    db.add(otp)
    await db.commit()
    await send_otp_email(email, code, purpose)
    return code


async def verify_otp(db: AsyncSession, email: str, code: str, purpose: str) -> bool:
    result = await db.execute(
        select(models.OTPCode)
        .where(
            models.OTPCode.email == email,
            models.OTPCode.purpose == purpose,
            models.OTPCode.used == False,  # noqa: E712
        )
        .order_by(models.OTPCode.created_at.desc())
    )
    otp = result.scalars().first()
    if otp is None:
        return False
    if otp.expires_at < datetime.now(timezone.utc):
        return False
    if otp.attempts >= OTP_MAX_ATTEMPTS:
        return False
    otp.attempts += 1
    if not verify_password(code, otp.code_hash):
        await db.commit()
        return False
    otp.used = True
    await db.commit()
    return True


# ---------------------------------------------------------------------------
# Pagination helpers (cursor-based on created_at + id)
# ---------------------------------------------------------------------------

def encode_cursor(created_at: datetime, id_: UUID) -> str:
    raw = f"{created_at.isoformat()}|{id_}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts, id_str = raw.split("|")
        return datetime.fromisoformat(ts), UUID(id_str)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid pagination cursor")


PAGE_SIZE = 20


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

async def idempotent(
    db: AsyncSession,
    key: Optional[str],
    endpoint: str,
    user_id: UUID,
):
    """Call at the top of a write endpoint. Returns a cached response dict
    if this Idempotency-Key was already processed, else None."""
    if not key:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Idempotency-Key header is required")
    result = await db.execute(select(models.IdempotencyKey).where(models.IdempotencyKey.key == key))
    existing = result.scalar_one_or_none()
    if existing:
        return existing.response_body, existing.status_code
    return None, None


async def store_idempotent_result(
    db: AsyncSession, key: str, user_id: UUID, endpoint: str, response_body: dict, status_code: int
):
    db.add(models.IdempotencyKey(
        key=key, user_id=user_id, endpoint=endpoint,
        response_body=response_body, status_code=status_code,
    ))
    await db.commit()


# ---------------------------------------------------------------------------
# Notification helper
# ---------------------------------------------------------------------------

async def push_notification(
    db: AsyncSession, user_id: UUID, type_: models.NotificationType,
    actor_id: Optional[UUID] = None, story_id: Optional[UUID] = None, message: str = "",
):
    db.add(models.Notification(
        user_id=user_id, type=type_, actor_id=actor_id, story_id=story_id, message=message,
    ))
    # commit happens with the caller's transaction


# ===========================================================================
# AUTH
# ===========================================================================

@app.post("/auth/signup", status_code=201)
async def signup(payload: schemas.SignupRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Profile).where(models.Profile.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    user = models.Profile(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=models.RoleEnum.reader,
    )
    db.add(user)
    await db.commit()
    await issue_otp(db, payload.email, "signup")
    return {"message": "Verification code sent"}


@app.post("/auth/verify-otp", response_model=schemas.TokenResponse)
async def verify_signup_otp(payload: schemas.VerifyOTPRequest, db: AsyncSession = Depends(get_db)):
    ok = await verify_otp(db, payload.email, payload.code, payload.purpose)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired code")

    if payload.purpose == "signup":
        result = await db.execute(select(models.Profile).where(models.Profile.email == payload.email))
        user = result.scalar_one()
        user.is_email_verified = True
        await db.commit()
        return create_token_pair(str(user.id))

    # purpose == "reset": issue a short-lived reset token instead of full login
    reset_token = create_token(payload.email, timedelta(minutes=15), "reset")
    return schemas.TokenResponse(access_token=reset_token, refresh_token="", token_type="reset")


@app.post("/auth/resend-otp")
async def resend_otp(payload: schemas.ResendOTPRequest, db: AsyncSession = Depends(get_db)):
    await issue_otp(db, payload.email, payload.purpose)
    return {"message": "Code resent"}


@app.post("/auth/login", response_model=schemas.TokenResponse)
async def login(payload: schemas.LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Profile).where(models.Profile.email == payload.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    if not user.is_email_verified:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Email not verified")
    return create_token_pair(str(user.id))


@app.post("/auth/refresh", response_model=schemas.TokenResponse)
async def refresh_token(payload: schemas.RefreshRequest):
    try:
        decoded = jwt.decode(payload.refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if decoded.get("type") != "refresh":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong token type")
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired refresh token")
    return create_token_pair(decoded["sub"])


@app.post("/auth/forgot-password")
async def forgot_password(payload: schemas.ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Profile).where(models.Profile.email == payload.email))
    if result.scalar_one_or_none():
        await issue_otp(db, payload.email, "reset")
    # Always return 200 regardless of whether the email exists, to avoid
    # leaking which emails are registered.
    return {"message": "If that email exists, a code has been sent"}


@app.post("/auth/reset-password")
async def reset_password(payload: schemas.ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    try:
        decoded = jwt.decode(payload.reset_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if decoded.get("type") != "reset" or decoded.get("sub") != payload.email:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid reset token")
    except JWTError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset token")

    result = await db.execute(select(models.Profile).where(models.Profile.email == payload.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    user.hashed_password = hash_password(payload.new_password)
    await db.commit()
    return {"message": "Password updated"}


@app.get("/auth/me", response_model=schemas.ProfileOut)
async def get_me(user: models.Profile = Depends(get_current_user)):
    # Fast, single lookup so the app can check session validity instantly
    # on launch without a flash of the wrong screen (see AGENTS.md).
    return user


@app.post("/auth/choose-role", response_model=schemas.ProfileOut)
async def choose_role(
    payload: schemas.ChooseRoleRequest,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user.role = payload.role
    user.is_writer = payload.role in (models.RoleEnum.writer, models.RoleEnum.both)
    await db.commit()
    await db.refresh(user)
    return user


# ===========================================================================
# PROFILE
# ===========================================================================

@app.get("/profiles/{profile_id}", response_model=schemas.ProfileOut)
async def get_profile(profile_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Profile).where(models.Profile.id == profile_id))
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Profile not found")
    return profile


@app.patch("/profiles/me", response_model=schemas.ProfileOut)
async def update_my_profile(
    payload: schemas.ProfileUpdate,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(user, field, value)
    await db.commit()
    await db.refresh(user)
    return user


@app.get("/profiles/me/avatar-signature", response_model=schemas.CloudinarySignatureOut)
async def get_avatar_upload_signature(user: models.Profile = Depends(get_current_user)):
    """Signs a Cloudinary upload so the API's secret never reaches the app —
    the client uploads directly to Cloudinary using these signed params."""
    timestamp = int(datetime.now(timezone.utc).timestamp())
    params_to_sign = f"timestamp={timestamp}&upload_preset={CLOUDINARY_UPLOAD_PRESET}"
    signature = hashlib.sha1((params_to_sign + CLOUDINARY_API_SECRET).encode()).hexdigest()
    return schemas.CloudinarySignatureOut(
        timestamp=timestamp,
        signature=signature,
        api_key=CLOUDINARY_API_KEY,
        cloud_name=CLOUDINARY_CLOUD_NAME,
        upload_preset=CLOUDINARY_UPLOAD_PRESET,
    )


# ===========================================================================
# STORIES / SHORTS
# ===========================================================================

def _story_query():
    return select(models.Story).options(selectinload(models.Story.author))


@app.post("/stories", response_model=schemas.StoryOut, status_code=201)
async def create_story(
    payload: schemas.StoryCreate,
    user: models.Profile = Depends(require_writer),
    db: AsyncSession = Depends(get_db),
):
    story = models.Story(user_id=user.id, **payload.model_dump())
    db.add(story)
    await db.commit()
    result = await _story_query().where(models.Story.id == story.id)
    return (await db.execute(result)).scalar_one()


@app.patch("/stories/{story_id}", response_model=schemas.StoryOut)
async def update_story(
    story_id: UUID,
    payload: schemas.StoryUpdate,
    user: models.Profile = Depends(require_writer),
    db: AsyncSession = Depends(get_db),
):
    result = await _story_query().where(models.Story.id == story_id)
    story = (await db.execute(result)).scalar_one_or_none()
    if not story:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Story not found")
    if story.user_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not your story")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(story, field, value)
    if payload.status == models.StoryStatus.published:
        user.total_stories += 1
    await db.commit()
    await db.refresh(story)
    return story


@app.get("/stories/feed", response_model=schemas.PaginatedResponse[schemas.StoryCardOut])
async def get_feed(
    cursor: Optional[str] = None,
    category: Optional[str] = None,
    content_type: Optional[models.ContentType] = None,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = _story_query().where(models.Story.status == models.StoryStatus.published)
    if category:
        q = q.where(models.Story.category == category)
    if content_type:
        q = q.where(models.Story.content_type == content_type)
    if cursor:
        created_at, id_ = decode_cursor(cursor)
        q = q.where(
            (models.Story.created_at < created_at)
            | ((models.Story.created_at == created_at) & (models.Story.id < id_))
        )
    q = q.order_by(models.Story.created_at.desc(), models.Story.id.desc()).limit(PAGE_SIZE + 1)

    rows = (await db.execute(q)).scalars().all()
    has_more = len(rows) > PAGE_SIZE
    rows = rows[:PAGE_SIZE]
    next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id) if has_more and rows else None
    return schemas.PaginatedResponse(items=rows, next_cursor=next_cursor, has_more=has_more)


@app.get("/stories/explore", response_model=schemas.PaginatedResponse[schemas.StoryCardOut])
async def explore_stories(
    cursor: Optional[str] = None,
    category: Optional[str] = None,
    content_type: Optional[models.ContentType] = None,
    trending: bool = False,
    db: AsyncSession = Depends(get_db),
):
    q = _story_query().where(models.Story.status == models.StoryStatus.published)
    if category:
        q = q.where(models.Story.category == category)
    if content_type:
        q = q.where(models.Story.content_type == content_type)

    if trending:
        q = q.order_by(models.Story.views.desc(), models.Story.id.desc()).limit(PAGE_SIZE)
        rows = (await db.execute(q)).scalars().all()
        return schemas.PaginatedResponse(items=rows, next_cursor=None, has_more=False)

    if cursor:
        created_at, id_ = decode_cursor(cursor)
        q = q.where(
            (models.Story.created_at < created_at)
            | ((models.Story.created_at == created_at) & (models.Story.id < id_))
        )
    q = q.order_by(models.Story.created_at.desc(), models.Story.id.desc()).limit(PAGE_SIZE + 1)
    rows = (await db.execute(q)).scalars().all()
    has_more = len(rows) > PAGE_SIZE
    rows = rows[:PAGE_SIZE]
    next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id) if has_more and rows else None
    return schemas.PaginatedResponse(items=rows, next_cursor=next_cursor, has_more=has_more)


@app.get("/stories/me", response_model=schemas.PaginatedResponse[schemas.StoryCardOut])
async def my_stories(
    status_filter: Optional[models.StoryStatus] = None,
    cursor: Optional[str] = None,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = _story_query().where(models.Story.user_id == user.id)
    if status_filter:
        q = q.where(models.Story.status == status_filter)
    if cursor:
        created_at, id_ = decode_cursor(cursor)
        q = q.where(
            (models.Story.created_at < created_at)
            | ((models.Story.created_at == created_at) & (models.Story.id < id_))
        )
    q = q.order_by(models.Story.created_at.desc(), models.Story.id.desc()).limit(PAGE_SIZE + 1)
    rows = (await db.execute(q)).scalars().all()
    has_more = len(rows) > PAGE_SIZE
    rows = rows[:PAGE_SIZE]
    next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id) if has_more and rows else None
    return schemas.PaginatedResponse(items=rows, next_cursor=next_cursor, has_more=has_more)


@app.get("/stories/{story_id}", response_model=schemas.StoryOut)
async def get_story(
    story_id: UUID,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await _story_query().where(models.Story.id == story_id)
    story = (await db.execute(result)).scalar_one_or_none()
    if not story:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Story not found")
    if story.status == models.StoryStatus.draft and story.user_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This draft isn't published yet")
    return story


@app.post("/stories/{story_id}/view")
async def register_view(
    story_id: UUID,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Dedup: one counted view per (user, story) via the unique constraint
    on read_history — repeat calls just no-op instead of inflating views."""
    existing = await db.execute(
        select(models.ReadHistory).where(
            models.ReadHistory.user_id == user.id, models.ReadHistory.story_id == story_id
        )
    )
    if existing.scalar_one_or_none():
        return {"message": "Already counted"}

    db.add(models.ReadHistory(user_id=user.id, story_id=story_id))
    await db.execute(
        models.Story.__table__.update()
        .where(models.Story.id == story_id)
        .values(views=models.Story.views + 1)
    )
    await db.commit()
    return {"message": "View counted"}


@app.patch("/stories/{story_id}/read-progress")
async def update_read_progress(
    story_id: UUID,
    payload: schemas.ReadProgressUpdate,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(models.ReadHistory).where(
            models.ReadHistory.user_id == user.id, models.ReadHistory.story_id == story_id
        )
    )
    rh = result.scalar_one_or_none()
    if not rh:
        rh = models.ReadHistory(user_id=user.id, story_id=story_id)
        db.add(rh)
    rh.progress_pct = payload.progress_pct

    reward_issued = False
    if payload.progress_pct >= 100 and not rh.completed:
        rh.completed = True
        reward_issued = True
        # Reader earns a small reward for completing an article.
        db.add(models.Transaction(
            user_id=user.id, type=models.TransactionType.credit, amount=Decimal("0.20"),
            description="Reading reward", status=models.TransactionStatus.success,
        ))
        user.total_earnings += Decimal("0.20")
    await db.commit()
    return {"progress_pct": rh.progress_pct, "reward_issued": reward_issued}


@app.post("/stories/{story_id}/unlock", response_model=schemas.UnlockStoryResponse)
async def unlock_story(
    story_id: UUID,
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    cached, cached_status = await idempotent(db, idempotency_key, "unlock_story", user.id)
    if cached:
        return cached

    result = await db.execute(select(models.Story).where(models.Story.id == story_id))
    story = result.scalar_one_or_none()
    if not story or not story.is_premium:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Story is not a paid unlock")

    # Balance check against credited transactions minus prior debits/withdrawals.
    balance_result = await db.execute(
        select(sqlfunc.coalesce(sqlfunc.sum(models.Transaction.amount), 0)).where(
            models.Transaction.user_id == user.id,
            models.Transaction.status == models.TransactionStatus.success,
        )
    )
    balance = balance_result.scalar() or Decimal("0")
    if balance < story.premium_price:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Insufficient balance — top up first")

    db.add(models.Transaction(
        user_id=user.id, type=models.TransactionType.debit, amount=-story.premium_price,
        description=f"Unlocked '{story.title}'", status=models.TransactionStatus.success,
        reference=idempotency_key,
    ))
    db.add(models.Transaction(
        user_id=story.user_id, type=models.TransactionType.credit, amount=story.premium_price,
        description=f"Unlock earnings: '{story.title}'", status=models.TransactionStatus.success,
    ))
    story.earnings += story.premium_price
    await push_notification(
        db, story.user_id, models.NotificationType.unlock, actor_id=user.id, story_id=story.id,
        message=f"Someone unlocked '{story.title}'",
    )
    await db.commit()

    response = schemas.UnlockStoryResponse(
        story_id=story.id, amount_charged=story.premium_price, new_balance=balance - story.premium_price,
    ).model_dump(mode="json")
    await store_idempotent_result(db, idempotency_key, user.id, "unlock_story", response, 200)
    return response


@app.post("/stories/{story_id}/like")
async def like_story(
    story_id: UUID,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(models.Story).where(models.Story.id == story_id))
    story = result.scalar_one_or_none()
    if not story:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Story not found")
    story.likes += 1
    await push_notification(
        db, story.user_id, models.NotificationType.like, actor_id=user.id, story_id=story.id,
        message="Someone liked your story",
    )
    await db.commit()
    return {"likes": story.likes}


# ===========================================================================
# COMMENTS
# ===========================================================================

@app.get("/stories/{story_id}/comments", response_model=schemas.PaginatedResponse[schemas.CommentOut])
async def list_comments(story_id: UUID, cursor: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    q = (
        select(models.Comment)
        .options(selectinload(models.Comment.__mapper__.relationships))
        .where(models.Comment.story_id == story_id)
    )
    if cursor:
        created_at, id_ = decode_cursor(cursor)
        q = q.where(
            (models.Comment.created_at < created_at)
            | ((models.Comment.created_at == created_at) & (models.Comment.id < id_))
        )
    q = q.order_by(models.Comment.created_at.desc(), models.Comment.id.desc()).limit(PAGE_SIZE + 1)
    rows = (await db.execute(q)).scalars().all()
    has_more = len(rows) > PAGE_SIZE
    rows = rows[:PAGE_SIZE]
    next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id) if has_more and rows else None
    return schemas.PaginatedResponse(items=rows, next_cursor=next_cursor, has_more=has_more)


@app.post("/stories/{story_id}/comments", response_model=schemas.CommentOut, status_code=201)
async def create_comment(
    story_id: UUID,
    payload: schemas.CommentCreate,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(models.Story).where(models.Story.id == story_id))
    story = result.scalar_one_or_none()
    if not story:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Story not found")

    comment = models.Comment(story_id=story_id, user_id=user.id, **payload.model_dump())
    db.add(comment)
    story.comments_count += 1
    await push_notification(
        db, story.user_id, models.NotificationType.comment, actor_id=user.id, story_id=story.id,
        message="New comment on your story",
    )
    await db.commit()
    await db.refresh(comment)
    comment.author = user
    return comment


# ===========================================================================
# FOLLOWS
# ===========================================================================

@app.post("/follows/{target_id}", response_model=schemas.FollowStatusOut)
async def follow_user(
    target_id: UUID,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if target_id == user.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot follow yourself")
    existing = await db.execute(
        select(models.Follow).where(
            models.Follow.follower_id == user.id, models.Follow.following_id == target_id
        )
    )
    if not existing.scalar_one_or_none():
        db.add(models.Follow(follower_id=user.id, following_id=target_id))
        user.following += 1
        target = await db.execute(select(models.Profile).where(models.Profile.id == target_id))
        target_profile = target.scalar_one()
        target_profile.followers += 1
        await push_notification(
            db, target_id, models.NotificationType.follow, actor_id=user.id,
            message="started following you",
        )
        await db.commit()
    return schemas.FollowStatusOut(following=True, followers_count=user.following)


@app.delete("/follows/{target_id}", response_model=schemas.FollowStatusOut)
async def unfollow_user(
    target_id: UUID,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(models.Follow).where(
            models.Follow.follower_id == user.id, models.Follow.following_id == target_id
        )
    )
    follow = result.scalar_one_or_none()
    if follow:
        await db.delete(follow)
        user.following = max(0, user.following - 1)
        target = await db.execute(select(models.Profile).where(models.Profile.id == target_id))
        target_profile = target.scalar_one()
        target_profile.followers = max(0, target_profile.followers - 1)
        await db.commit()
    return schemas.FollowStatusOut(following=False, followers_count=user.following)


# ===========================================================================
# NOTIFICATIONS
# ===========================================================================

@app.get("/notifications", response_model=schemas.PaginatedResponse[schemas.NotificationOut])
async def list_notifications(
    cursor: Optional[str] = None,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(models.Notification).where(models.Notification.user_id == user.id)
    if cursor:
        created_at, id_ = decode_cursor(cursor)
        q = q.where(
            (models.Notification.created_at < created_at)
            | ((models.Notification.created_at == created_at) & (models.Notification.id < id_))
        )
    q = q.order_by(models.Notification.created_at.desc(), models.Notification.id.desc()).limit(PAGE_SIZE + 1)
    rows = (await db.execute(q)).scalars().all()
    has_more = len(rows) > PAGE_SIZE
    rows = rows[:PAGE_SIZE]
    next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id) if has_more and rows else None
    return schemas.PaginatedResponse(items=rows, next_cursor=next_cursor, has_more=has_more)


@app.patch("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: UUID,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(models.Notification).where(
            models.Notification.id == notification_id, models.Notification.user_id == user.id
        )
    )
    notif = result.scalar_one_or_none()
    if not notif:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Notification not found")
    notif.is_read = True
    await db.commit()
    return {"message": "Marked as read"}


# ===========================================================================
# LIBRARY (saved stories + read history)
# ===========================================================================

@app.post("/library/save/{story_id}", status_code=201)
async def save_story(
    story_id: UUID, user: models.Profile = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    existing = await db.execute(
        select(models.SavedStory).where(
            models.SavedStory.user_id == user.id, models.SavedStory.story_id == story_id
        )
    )
    if not existing.scalar_one_or_none():
        db.add(models.SavedStory(user_id=user.id, story_id=story_id))
        await db.commit()
    return {"message": "Saved"}


@app.delete("/library/save/{story_id}")
async def unsave_story(
    story_id: UUID, user: models.Profile = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(models.SavedStory).where(
            models.SavedStory.user_id == user.id, models.SavedStory.story_id == story_id
        )
    )
    saved = result.scalar_one_or_none()
    if saved:
        await db.delete(saved)
        await db.commit()
    return {"message": "Removed"}


@app.get("/library/saved", response_model=schemas.PaginatedResponse[schemas.StoryCardOut])
async def list_saved(
    cursor: Optional[str] = None,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = (
        _story_query()
        .join(models.SavedStory, models.SavedStory.story_id == models.Story.id)
        .where(models.SavedStory.user_id == user.id)
    )
    if cursor:
        created_at, id_ = decode_cursor(cursor)
        q = q.where(
            (models.Story.created_at < created_at)
            | ((models.Story.created_at == created_at) & (models.Story.id < id_))
        )
    q = q.order_by(models.Story.created_at.desc(), models.Story.id.desc()).limit(PAGE_SIZE + 1)
    rows = (await db.execute(q)).scalars().all()
    has_more = len(rows) > PAGE_SIZE
    rows = rows[:PAGE_SIZE]
    next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id) if has_more and rows else None
    return schemas.PaginatedResponse(items=rows, next_cursor=next_cursor, has_more=has_more)


@app.get("/library/history", response_model=schemas.PaginatedResponse[schemas.StoryCardOut])
async def list_history(
    cursor: Optional[str] = None,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = (
        _story_query()
        .join(models.ReadHistory, models.ReadHistory.story_id == models.Story.id)
        .where(models.ReadHistory.user_id == user.id)
    )
    if cursor:
        created_at, id_ = decode_cursor(cursor)
        q = q.where(
            (models.Story.created_at < created_at)
            | ((models.Story.created_at == created_at) & (models.Story.id < id_))
        )
    q = q.order_by(models.Story.created_at.desc(), models.Story.id.desc()).limit(PAGE_SIZE + 1)
    rows = (await db.execute(q)).scalars().all()
    has_more = len(rows) > PAGE_SIZE
    rows = rows[:PAGE_SIZE]
    next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id) if has_more and rows else None
    return schemas.PaginatedResponse(items=rows, next_cursor=next_cursor, has_more=has_more)


# ===========================================================================
# EARNINGS
# ===========================================================================

@app.get("/earnings/summary", response_model=schemas.EarningsSummaryOut)
async def earnings_summary(
    user: models.Profile = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    balance_result = await db.execute(
        select(sqlfunc.coalesce(sqlfunc.sum(models.Transaction.amount), 0)).where(
            models.Transaction.user_id == user.id,
            models.Transaction.status == models.TransactionStatus.success,
        )
    )
    balance = balance_result.scalar() or Decimal("0")

    reads_result = await db.execute(
        select(sqlfunc.count()).select_from(models.ReadHistory).where(
            models.ReadHistory.user_id == user.id, models.ReadHistory.completed == True  # noqa: E712
        )
    )
    reads_count = reads_result.scalar() or 0

    period_start = datetime.now(timezone.utc) - timedelta(days=1)
    period_result = await db.execute(
        select(sqlfunc.coalesce(sqlfunc.sum(models.Transaction.amount), 0)).where(
            models.Transaction.user_id == user.id,
            models.Transaction.status == models.TransactionStatus.success,
            models.Transaction.type == models.TransactionType.credit,
            models.Transaction.created_at >= period_start,
        )
    )
    revenue_today = period_result.scalar() or Decimal("0")

    return schemas.EarningsSummaryOut(
        available_balance=balance,
        all_time_earned=user.total_earnings,
        reads_count=reads_count,
        revenue_this_period=revenue_today,
    )


@app.get("/earnings/transactions", response_model=schemas.PaginatedResponse[schemas.TransactionOut])
async def list_transactions(
    cursor: Optional[str] = None,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(models.Transaction).where(models.Transaction.user_id == user.id)
    if cursor:
        created_at, id_ = decode_cursor(cursor)
        q = q.where(
            (models.Transaction.created_at < created_at)
            | ((models.Transaction.created_at == created_at) & (models.Transaction.id < id_))
        )
    q = q.order_by(models.Transaction.created_at.desc(), models.Transaction.id.desc()).limit(PAGE_SIZE + 1)
    rows = (await db.execute(q)).scalars().all()
    has_more = len(rows) > PAGE_SIZE
    rows = rows[:PAGE_SIZE]
    next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id) if has_more and rows else None
    return schemas.PaginatedResponse(items=rows, next_cursor=next_cursor, has_more=has_more)


# ===========================================================================
# WITHDRAWALS
# ===========================================================================

@app.post("/withdrawals", response_model=schemas.WithdrawalOut, status_code=201)
async def request_withdrawal(
    payload: schemas.WithdrawalCreate,
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    user: models.Profile = Depends(require_writer),
    db: AsyncSession = Depends(get_db),
):
    cached, _ = await idempotent(db, idempotency_key, "withdrawal", user.id)
    if cached:
        return cached

    balance_result = await db.execute(
        select(sqlfunc.coalesce(sqlfunc.sum(models.Transaction.amount), 0)).where(
            models.Transaction.user_id == user.id,
            models.Transaction.status == models.TransactionStatus.success,
        )
    )
    balance = balance_result.scalar() or Decimal("0")
    if balance < payload.amount:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Insufficient balance")

    withdrawal = models.Withdrawal(
        user_id=user.id, reference=idempotency_key, **payload.model_dump()
    )
    db.add(withdrawal)
    db.add(models.Transaction(
        user_id=user.id, type=models.TransactionType.withdrawal, amount=-payload.amount,
        description="Withdrawal requested", status=models.TransactionStatus.pending,
        reference=idempotency_key,
    ))
    await db.commit()
    await db.refresh(withdrawal)

    response = schemas.WithdrawalOut.model_validate(withdrawal).model_dump(mode="json")
    await store_idempotent_result(db, idempotency_key, user.id, "withdrawal", response, 201)
    return withdrawal


@app.get("/withdrawals", response_model=schemas.PaginatedResponse[schemas.WithdrawalOut])
async def list_withdrawals(
    cursor: Optional[str] = None,
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(models.Withdrawal).where(models.Withdrawal.user_id == user.id)
    if cursor:
        created_at, id_ = decode_cursor(cursor)
        q = q.where(
            (models.Withdrawal.created_at < created_at)
            | ((models.Withdrawal.created_at == created_at) & (models.Withdrawal.id < id_))
        )
    q = q.order_by(models.Withdrawal.created_at.desc(), models.Withdrawal.id.desc()).limit(PAGE_SIZE + 1)
    rows = (await db.execute(q)).scalars().all()
    has_more = len(rows) > PAGE_SIZE
    rows = rows[:PAGE_SIZE]
    next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id) if has_more and rows else None
    return schemas.PaginatedResponse(items=rows, next_cursor=next_cursor, has_more=has_more)


# ===========================================================================
# PAYMENTS (Paystack) — e.g. reader topping up their in-app balance
# ===========================================================================

@app.post("/payments/initialize", response_model=schemas.PaystackInitResponse)
async def initialize_payment(
    payload: schemas.PaystackInitRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    user: models.Profile = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    cached, _ = await idempotent(db, idempotency_key, "payment_init", user.id)
    if cached:
        return cached

    reference = f"ernc_{idempotency_key}"
    amount_kobo = int(payload.amount * 100)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{PAYSTACK_BASE_URL}/transaction/initialize",
            headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"},
            json={"email": user.email, "amount": amount_kobo, "reference": reference},
        )
    data = resp.json()
    if not data.get("status"):
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Paystack initialization failed")

    db.add(models.Transaction(
        user_id=user.id, type=models.TransactionType.credit, amount=payload.amount,
        description="Wallet top-up", status=models.TransactionStatus.pending, reference=reference,
    ))
    await db.commit()

    response = schemas.PaystackInitResponse(
        authorization_url=data["data"]["authorization_url"],
        access_code=data["data"]["access_code"],
        reference=reference,
    ).model_dump(mode="json")
    await store_idempotent_result(db, idempotency_key, user.id, "payment_init", response, 200)
    return response


@app.post("/payments/webhook")
async def paystack_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    """Paystack calls this after a payment completes. Verifies the signature
    so only genuine Paystack requests can mark a transaction successful."""
    body = await request.body()
    signature = request.headers.get("x-paystack-signature", "")
    expected = hmac.new(PAYSTACK_SECRET_KEY.encode(), body, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid webhook signature")

    event = json.loads(body)
    if event.get("event") == "charge.success":
        reference = event["data"]["reference"]
        result = await db.execute(
            select(models.Transaction).where(models.Transaction.reference == reference)
        )
        txn = result.scalar_one_or_none()
        if txn and txn.status == models.TransactionStatus.pending:
            txn.status = models.TransactionStatus.success
            user_result = await db.execute(select(models.Profile).where(models.Profile.id == txn.user_id))
            user = user_result.scalar_one()
            user.total_earnings += txn.amount if txn.amount > 0 else Decimal("0")
            await db.commit()
    return {"message": "ok"}


@app.get("/payments/verify/{reference}", response_model=schemas.PaystackVerifyResponse)
async def verify_payment(reference: str, user: models.Profile = Depends(get_current_user)):
    """Manual verification fallback if the app polls instead of relying on webhook alone."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{PAYSTACK_BASE_URL}/transaction/verify/{reference}",
            headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"},
        )
    data = resp.json()
    if not data.get("status"):
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Paystack verification failed")
    tx = data["data"]
    return schemas.PaystackVerifyResponse(
        reference=reference, status=tx["status"], amount=Decimal(tx["amount"]) / 100
    )


@app.get("/health")
async def health():
    return {"status": "ok"}
