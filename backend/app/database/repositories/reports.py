import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from app.database.mongodb import db_manager


class ThreatReportRepository:
    collection_name = "reports"

    @classmethod
    async def create_report(cls, report_data: Dict[str, Any]) -> Dict[str, Any]:
        report_id = str(uuid.uuid4())
        report_data["report_id"] = report_id
        report_data["created_at"] = datetime.now(timezone.utc).isoformat()
        report_data["status"] = "received"

        if not db_manager.use_in_memory and db_manager.db is not None:
            try:
                await db_manager.db[cls.collection_name].insert_one(report_data)
                return report_data
            except Exception:
                pass

        db_manager._in_memory_reports.insert(0, report_data)
        return report_data

    @classmethod
    async def get_all_reports(cls, limit: int = 50) -> List[Dict[str, Any]]:
        if not db_manager.use_in_memory and db_manager.db is not None:
            try:
                cursor = db_manager.db[cls.collection_name].find({}).sort("created_at", -1).limit(limit)
                res = []
                async for doc in cursor:
                    doc.pop("_id", None)
                    res.append(doc)
                return res
            except Exception:
                pass

        return db_manager._in_memory_reports[:limit]

