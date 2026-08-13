"""
database.py — Async SQLAlchemy setup, connecting to the Supabase-hosted
Postgres database. Supabase is used here ONLY as the managed Postgres
instance — no Supabase Auth/PostgREST/client SDK is used anywhere.
"""
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from dotenv import load_dotenv

load_dotenv()

# Use Supabase's connection pooler (port 6543, pgbouncer) for serverless-friendly
# pooling, or port 5432 for a persistent server process. Get this from:
# Supabase Dashboard -> Project Settings -> Database -> Connection string (URI)
# Example: postgresql+asyncpg://postgres.xxxx:PASSWORD@aws-0-region.pooler.supabase.com:6543/postgres
DATABASE_URL = os.environ["DATABASE_URL"]

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()


async def get_db():
    """FastAPI dependency — yields a request-scoped DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
