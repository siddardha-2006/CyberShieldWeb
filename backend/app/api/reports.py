from fastapi import APIRouter
from app.schemas.report import ThreatReportRequest, ThreatReportResponse
from app.core.security import generate_hmac_identifier
from app.database.repositories.reports import ThreatReportRepository

router = APIRouter(prefix="/reports", tags=["Threat Reporting"])


@router.post("", response_model=ThreatReportResponse)
async def submit_threat_report(req: ThreatReportRequest):
    target_hmac = generate_hmac_identifier(req.target)
    report_data = {
        "analysis_id": req.analysis_id,
        "target_hmac": target_hmac,
        "threat_category": req.threat_category,
        "user_comments": req.user_comments
    }
    created = await ThreatReportRepository.create_report(report_data)
    return ThreatReportResponse(
        report_id=created["report_id"],
        target_hmac=target_hmac,
        threat_category=req.threat_category,
        status="received",
        created_at=created["created_at"],
        message="Threat indicator successfully logged into community intelligence."
    )


@router.get("")
async def get_all_reports():
    reports = await ThreatReportRepository.get_all_reports()
    return {"reports": reports, "count": len(reports)}

