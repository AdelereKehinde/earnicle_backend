"""
models.py — SQLAlchemy ORM models. Table shapes mirror the original
Supabase schema; only auth now lives here instead of Supabase Auth
(hashed_password, otp_codes) since we no longer use the Supabase SDK.
"""
import uuid
import enum
from datetime import datetime
from sqlalchemy import (
    Column, String, Text, Boolean, Integer, Numeric, ForeignKey,
    DateTime, ARRAY, Enum, UniqueConstraint, CheckConstraint, JSON, func
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base


def gen_uuid():
    return uuid.uuid4()


class RoleEnum(str, enum.Enum):
    reader = "reader"
    writer = "writer"
    both = "both"


class ContentType(str, enum.Enum):
    story = "story"
    short = "short"


class StoryStatus(str, enum.Enum):
    draft = "draft"
    published = "published"
    archived = "archived"


class TransactionType(str, enum.Enum):
    credit = "credit"
    debit = "debit"
    withdrawal = "withdrawal"


class TransactionStatus(str, enum.Enum):
    pending = "pending"
    success = "success"
    failed = "failed"


class WithdrawalStatus(str, enum.Enum):
    pending = "pending"
    processing = "processing"
    completed = "completed"
    failed = "failed"


class NotificationType(str, enum.Enum):
    follow = "follow"
    comment = "comment"
    like = "like"
    unlock = "unlock"
    membership = "membership"
    payout = "payout"


class Profile(Base):
    __tablename__ = "profiles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    username = Column(String, unique=True)
    role = Column(Enum(RoleEnum), default=RoleEnum.reader, nullable=False)
    bio = Column(Text)
    avatar_url = Column(String)
    followers = Column(Integer, default=0)
    following = Column(Integer, default=0)
    total_earnings = Column(Numeric(10, 2), default=0)
    total_stories = Column(Integer, default=0)
    is_writer = Column(Boolean, default=False)
    is_top_writer = Column(Boolean, default=False)
    is_pro_member = Column(Boolean, default=False)
    is_email_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    stories = relationship("Story", back_populates="author", foreign_keys="Story.user_id")


class Story(Base):
    __tablename__ = "stories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="CASCADE"), index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    excerpt = Column(Text)
    category = Column(String)
    tags = Column(ARRAY(String))
    cover_image = Column(String)
    content_type = Column(Enum(ContentType), default=ContentType.story, nullable=False)
    reading_time = Column(Integer, default=5)
    is_premium = Column(Boolean, default=False)
    premium_price = Column(Numeric(10, 2), default=0)
    views = Column(Integer, default=0)
    likes = Column(Integer, default=0)
    shares = Column(Integer, default=0)
    comments_count = Column(Integer, default=0)
    earnings = Column(Numeric(10, 2), default=0)
    status = Column(Enum(StoryStatus), default=StoryStatus.draft, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    author = relationship("Profile", back_populates="stories", foreign_keys=[user_id])


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="CASCADE"), index=True)
    type = Column(Enum(TransactionType), nullable=False)
    amount = Column(Numeric(10, 2), nullable=False)
    description = Column(Text)
    reference = Column(String, unique=True, index=True)
    status = Column(Enum(TransactionStatus), default=TransactionStatus.pending)
    extra = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class Withdrawal(Base):
    __tablename__ = "withdrawals"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="CASCADE"), index=True)
    amount = Column(Numeric(10, 2), nullable=False)
    bank_name = Column(String)
    account_number = Column(String)
    account_name = Column(String)
    reference = Column(String, unique=True, index=True)
    status = Column(Enum(WithdrawalStatus), default=WithdrawalStatus.pending)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    processed_at = Column(DateTime(timezone=True))


class ReadHistory(Base):
    __tablename__ = "read_history"
    __table_args__ = (UniqueConstraint("user_id", "story_id", name="uq_read_once"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="CASCADE"), index=True)
    story_id = Column(UUID(as_uuid=True), ForeignKey("stories.id", ondelete="CASCADE"), index=True)
    progress_pct = Column(Integer, default=0)
    completed = Column(Boolean, default=False)
    read_at = Column(DateTime(timezone=True), server_default=func.now())


class Follow(Base):
    __tablename__ = "follows"

    follower_id = Column(UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="CASCADE"), primary_key=True)
    following_id = Column(UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="CASCADE"), primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Comment(Base):
    __tablename__ = "comments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    story_id = Column(UUID(as_uuid=True), ForeignKey("stories.id", ondelete="CASCADE"), index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="CASCADE"))
    content = Column(Text, nullable=False)
    parent_id = Column(UUID(as_uuid=True), ForeignKey("comments.id", ondelete="CASCADE"), nullable=True)
    likes = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="CASCADE"), index=True)
    type = Column(Enum(NotificationType), nullable=False)
    actor_id = Column(UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="SET NULL"), nullable=True)
    story_id = Column(UUID(as_uuid=True), ForeignKey("stories.id", ondelete="CASCADE"), nullable=True)
    message = Column(Text)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class SavedStory(Base):
    __tablename__ = "saved_stories"

    user_id = Column(UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="CASCADE"), primary_key=True)
    story_id = Column(UUID(as_uuid=True), ForeignKey("stories.id", ondelete="CASCADE"), primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class OTPCode(Base):
    """Short-lived OTP codes for signup verification and password reset."""
    __tablename__ = "otp_codes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    email = Column(String, nullable=False, index=True)
    code_hash = Column(String, nullable=False)
    purpose = Column(String, nullable=False)  # 'signup' | 'reset'
    attempts = Column(Integer, default=0)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class IdempotencyKey(Base):
    """Stores the response of a previously processed request so retried
    writes (payments, withdrawals) with the same key are never double-run."""
    __tablename__ = "idempotency_keys"

    key = Column(String, primary_key=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="CASCADE"))
    endpoint = Column(String, nullable=False)
    response_body = Column(JSON, nullable=False)
    status_code = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
