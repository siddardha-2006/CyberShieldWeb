import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from app.database.mongodb import db_manager


class UserRepository:
    collection_name = "users"

    @classmethod
    async def create_user(cls, user_data: Dict[str, Any]) -> Dict[str, Any]:
        user_id = str(uuid.uuid4())
        user_data["id"] = user_id
        user_data["created_at"] = datetime.now(timezone.utc).isoformat()

        if not db_manager.use_in_memory and db_manager.db is not None:
            try:
                await db_manager.db[cls.collection_name].insert_one(user_data)
                return user_data
            except Exception:
                pass

        db_manager._in_memory_users.append(user_data)
        return user_data

    @classmethod
    async def get_by_username_or_email(cls, identifier: str) -> Optional[Dict[str, Any]]:
        id_lower = identifier.lower().strip()
        if not db_manager.use_in_memory and db_manager.db is not None:
            try:
                doc = await db_manager.db[cls.collection_name].find_one({
                    "$or": [{"username": id_lower}, {"email": id_lower}]
                })
                if doc:
                    doc.pop("_id", None)
                    return doc
            except Exception:
                pass

        for u in db_manager._in_memory_users:
            if u.get("username", "").lower() == id_lower or u.get("email", "").lower() == id_lower:
                return u
        return None

