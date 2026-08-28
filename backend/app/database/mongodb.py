import asyncio
from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings
from app.core.logging import logger


class DatabaseManager:
    client: Optional[AsyncIOMotorClient] = None
    db = None
    use_in_memory: bool = False
    
    # In-memory stores for fallback
    _in_memory_analyses: List[Dict[str, Any]] = []
    _in_memory_users: List[Dict[str, Any]] = []
    _in_memory_reports: List[Dict[str, Any]] = []

    @classmethod
    async def connect_db(cls):
        try:
            cls.client = AsyncIOMotorClient(
                settings.MONGODB_URI, 
                serverSelectionTimeoutMS=1500
            )
            # Ping database to test connectivity
            await cls.client.admin.command('ping')
            cls.db = cls.client[settings.MONGODB_DATABASE]
            cls.use_in_memory = False
            logger.info("Successfully connected to MongoDB.")
        except Exception as e:
            cls.use_in_memory = True
            logger.warning(f"MongoDB not available ({e}). Using in-memory persistent storage fallback.")

    @classmethod
    async def close_db(cls):
        if cls.client:
            cls.client.close()
            logger.info("Closed MongoDB connection.")


db_manager = DatabaseManager

