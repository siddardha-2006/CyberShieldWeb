from typing import List, Dict, Any, Optional
from app.database.mongodb import db_manager
from app.schemas.analysis import AnalysisResponse


class AnalysisRepository:
    collection_name = "analyses"

    @classmethod
    async def save_analysis(cls, response: AnalysisResponse) -> str:
        doc = response.model_dump()
        if not db_manager.use_in_memory and db_manager.db is not None:
            try:
                res = await db_manager.db[cls.collection_name].insert_one(doc)
                return str(res.inserted_id)
            except Exception:
                pass

        # In-memory storage fallback
        db_manager._in_memory_analyses.insert(0, doc)
        return response.analysis_id

    @classmethod
    async def get_by_id(cls, analysis_id: str) -> Optional[Dict[str, Any]]:
        if not db_manager.use_in_memory and db_manager.db is not None:
            try:
                doc = await db_manager.db[cls.collection_name].find_one({"analysis_id": analysis_id})
                if doc:
                    doc.pop("_id", None)
                    return doc
            except Exception:
                pass

        for doc in db_manager._in_memory_analyses:
            if doc.get("analysis_id") == analysis_id:
                return doc
        return None

    @classmethod
    async def get_recent_history(cls, limit: int = 50) -> List[Dict[str, Any]]:
        if not db_manager.use_in_memory and db_manager.db is not None:
            try:
                cursor = db_manager.db[cls.collection_name].find({}).sort("created_at", -1).limit(limit)
                results = []
                async for doc in cursor:
                    doc.pop("_id", None)
                    results.append(doc)
                return results
            except Exception:
                pass

        return db_manager._in_memory_analyses[:limit]

