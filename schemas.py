"""
schemas.py — Pydantic request/response models.
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional, List, Generic, TypeVar
from uuid import UUID
from decimal import Decimal
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from models import RoleEnum, ContentType, StoryStatus, TransactionType, TransactionStatus, NotificationType

T = TypeVar("T")


# ---------- Shared / pagination ----------

class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]
    next_cursor: Optional[str] = None
    has_more: bool = False


# ---------- Auth ----------

class SignupRequest(BaseModel):
    full_name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class VerifyOTPRequest(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6)
    purpose: str = Field(pattern="^(signup|reset)$")


class ResendOTPRequest(BaseModel):
    email: EmailStr
    purpose: str = Field(pattern="^(signup|reset)$")


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    reset_token: str
    new_password: str = Field(min_length=8)


class ChooseRoleRequest(BaseModel):
    role: RoleEnum


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


# ---------- Profile ----------

class ProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    full_name: Optional[str]
    username: Optional[str]
    role: RoleEnum
    bio: Optional[str]
    avatar_url: Optional[str]
    followers: int
    following: int
    total_earnings: Decimal
    total_stories: int
    is_writer: bool
    is_top_writer: bool
    is_pro_member: bool
    created_at: datetime


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    username: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None


class CloudinarySignatureOut(BaseModel):
    """Signed params for a direct-to-Cloudinary upload from the client."""
    timestamp: int
    signature: str
    api_key: str
    cloud_name: str
    upload_preset: str


# ---------- Stories ----------

class StoryCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1)
    excerpt: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = Field(default=None, max_length=5)
    cover_image: Optional[str] = None
    content_type: ContentType = ContentType.story
    is_premium: bool = False
    premium_price: Decimal = Decimal("0")


class StoryUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    excerpt: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    cover_image: Optional[str] = None
    is_premium: Optional[bool] = None
    premium_price: Optional[Decimal] = None
    status: Optional[StoryStatus] = None


class AuthorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    full_name: Optional[str]
    username: Optional[str]
    avatar_url: Optional[str]
    is_top_writer: bool
    is_pro_member: bool


class StoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    title: str
    content: str
    excerpt: Optional[str]
    category: Optional[str]
    tags: Optional[List[str]]
    cover_image: Optional[str]
    content_type: ContentType
    reading_time: int
    is_premium: bool
    premium_price: Decimal
    views: int
    likes: int
    shares: int
    comments_count: int
    status: StoryStatus
    created_at: datetime
    author: AuthorOut


class StoryCardOut(BaseModel):
    """Lighter payload for feed/explore lists."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    title: str
    excerpt: Optional[str]
    category: Optional[str]
    cover_image: Optional[str]
    content_type: ContentType
    reading_time: int
    is_premium: bool
    premium_price: Decimal
    likes: int
    comments_count: int
    shares: int
    created_at: datetime
    author: AuthorOut


# ---------- Reading / unlock ----------

class UnlockStoryResponse(BaseModel):
    story_id: UUID
    amount_charged: Decimal
    new_balance: Decimal


class ReadProgressUpdate(BaseModel):
    progress_pct: int = Field(ge=0, le=100)


# ---------- Comments ----------

class CommentCreate(BaseModel):
    content: str = Field(min_length=1, max_length=1000)
    parent_id: Optional[UUID] = None


class CommentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    content: str
    parent_id: Optional[UUID]
    likes: int
    created_at: datetime
    author: AuthorOut


# ---------- Follows ----------

class FollowStatusOut(BaseModel):
    following: bool
    followers_count: int


# ---------- Notifications ----------

class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    type: NotificationType
    actor_id: Optional[UUID]
    story_id: Optional[UUID]
    message: Optional[str]
    is_read: bool
    created_at: datetime


# ---------- Library ----------

class SavedStoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    story: StoryCardOut
    saved_at: datetime


# ---------- Earnings / transactions ----------

class TransactionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    type: TransactionType
    amount: Decimal
    description: Optional[str]
    status: TransactionStatus
    created_at: datetime


class EarningsSummaryOut(BaseModel):
    available_balance: Decimal
    all_time_earned: Decimal
    reads_count: int
    revenue_this_period: Decimal


# ---------- Withdrawals ----------

class WithdrawalCreate(BaseModel):
    amount: Decimal = Field(gt=0)
    bank_name: str
    account_number: str
    account_name: str


class WithdrawalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    amount: Decimal
    bank_name: str
    status: str
    created_at: datetime


# ---------- Payments (Paystack) ----------

class PaystackInitRequest(BaseModel):
    amount: Decimal = Field(gt=0)  # naira/major unit; converted to kobo server-side


class PaystackInitResponse(BaseModel):
    authorization_url: str
    access_code: str
    reference: str


class PaystackVerifyResponse(BaseModel):
    reference: str
    status: str
    amount: Decimal
