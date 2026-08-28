from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal


# Request Schemas
class UrlAnalysisRequest(BaseModel):
    url: str = Field(..., description="Target URL or domain to scan")


class MessageAnalysisRequest(BaseModel):
    text: str = Field(..., description="SMS or chat message text")
    sender: Optional[str] = Field(None, description="Sender phone or ID if known")


class EmailAnalysisRequest(BaseModel):
    raw_email: Optional[str] = Field(None, description="Full raw pasted email message text including headers or body")
    sender: Optional[str] = Field("", description="Sender email address if provided separately")
    subject: Optional[str] = Field("", description="Email subject line if provided separately")
    body: Optional[str] = Field("", description="Email body text if provided separately")
    reply_to: Optional[str] = Field(None, description="Reply-to header address")
    headers: Optional[Dict[str, str]] = Field(default_factory=dict)


class QrAnalysisRequest(BaseModel):
    image_base64: Optional[str] = Field(None, description="Base64 encoded QR image data")
    decoded_payload: Optional[str] = Field(None, description="Directly decoded QR string/URL")


class WebpageAnalysisRequest(BaseModel):
    url: str = Field(..., description="Target webpage URL")
    html_content: Optional[str] = Field(None, description="Raw HTML snapshot content")


class SocialAnalysisRequest(BaseModel):
    text: str = Field(..., description="Social media post or direct message content")
    platform: Optional[str] = Field("generic", description="Social platform context: telegram, discord, twitter, whatsapp, etc.")


# Normalized Internal Contract
class NormalizedInput(BaseModel):
    analysis_id: str
    input_type: Literal["url", "message", "email", "qr", "webpage", "social"]
    text: Optional[str] = ""
    urls: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    phones: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    indicator_hmac: str = ""


# Evidence & Engine Result Contracts
class EvidenceItem(BaseModel):
    engine: str
    code: str
    title: str
    description: str
    weight: int = 10
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    category: str = "general"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EngineResult(BaseModel):
    engine: Literal["rules", "nlp", "threat_intelligence", "behavior"]
    status: Literal["completed", "timeout", "error", "unavailable", "not_applicable"]
    score: int = Field(0, ge=0, le=100)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    classifications: Optional[Dict[str, float]] = None
    observations: Optional[Dict[str, Any]] = None
    sources: Optional[List[str]] = None
    latency_ms: int = 0
    error_message: Optional[str] = None


# Final Response Schemas
class RiskAssessment(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="Overall fused risk score 0-100")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Assessment confidence score 0.0-1.0")
    severity: Literal["safe", "suspicious", "high_risk", "critical"]
    category: str = Field(..., description="Primary threat category identified")
    secondary_categories: List[str] = Field(default_factory=list)
    recommended_action: Literal["ALLOW", "WARN", "DO_NOT_INTERACT", "REPORT"]
    action_details: str


class ExplainabilityResponse(BaseModel):
    summary: str
    key_reasons: List[str]
    evidence_breakdown: List[EvidenceItem]
    safe_steps: List[str]


class AnalysisResponse(BaseModel):
    analysis_id: str
    input_type: str
    indicator_hmac: str
    created_at: str = ""
    assessment: RiskAssessment
    engines: Dict[str, EngineResult]
    explainability: ExplainabilityResponse
    language_info: Optional[Dict[str, Any]] = None
    duration_ms: int
