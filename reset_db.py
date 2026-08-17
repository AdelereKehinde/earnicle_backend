# reset_db.py
import asyncio
from database import engine, Base
# Import all your models here so SQLAlchemy knows they exist
from models import Profile, Story, Transaction, Withdrawal, ReadHistory, Follow, Comment, Notification, SavedStory, OTPCode

async def reset_database():
    print("WARNING: This will delete ALL data in your Supabase database!")
    confirm = input("Are you sure you want to proceed? (yes/no): ")
    
    if confirm.lower() == "yes":
        # We must open a connection to the async engine
        async with engine.begin() as conn:
            print("Dropping all existing tables...")
            # We use conn.run_sync to safely run the synchronous drop command
            await conn.run_sync(Base.metadata.drop_all)
            
            print("Creating all new tables from your models...")
            # We use conn.run_sync to safely run the synchronous create command
            await conn.run_sync(Base.metadata.create_all)
            
        print("Success! Database reset complete.")
    else:
        print("Database reset cancelled.")

if __name__ == "__main__":
    # Since it is an async function, we must run it inside an event loop
    asyncio.run(reset_database())
