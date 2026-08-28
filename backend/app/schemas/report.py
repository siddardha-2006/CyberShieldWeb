from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class ThreatReportRequest(BaseModel):
    analysis_id: Optional[str] = None
    target: str = Field(..., description="Target URL, phone number, email, or content snippet being reported")
    threat_category: str = Field("phishing", description="Phishing, Malware, Scam, Impersonation, etc.")
    user_comments: Optional[str] = Field(None, description="Optional notes or context from user")


class ThreatReportResponse(BaseModel):
    report_id: str
    target_hmac: str
    threat_category: str
    status: str = "received"
    created_at: str
    message: str

