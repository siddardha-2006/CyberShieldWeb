from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from app.database.repositories.analyses import AnalysisRepository

router = APIRouter(prefix="/history", tags=["History"])


@router.get("")
async def get_history(limit: int = Query(25, ge=1, le=100)):
    records = await AnalysisRepository.get_recent_history(limit=limit)
    return {"analyses": records, "total": len(records)}


@router.get("/{analysis_id}")
async def get_analysis_by_id(analysis_id: str):
    record = await AnalysisRepository.get_by_id(analysis_id)
    if not record:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return record

