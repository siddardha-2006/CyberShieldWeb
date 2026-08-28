from fastapi import APIRouter, HTTPException, Depends
from app.schemas.analysis import (
    UrlAnalysisRequest,
    MessageAnalysisRequest,
    EmailAnalysisRequest,
    QrAnalysisRequest,
    WebpageAnalysisRequest,
    SocialAnalysisRequest,
    AnalysisResponse
)
from app.normalization.normalizer import ContentNormalizer
from app.orchestration.analyzer import SecurityAnalyzer
from app.database.repositories.analyses import AnalysisRepository

router = APIRouter(prefix="/analyze", tags=["Detection & Analysis"])


@router.post("/url", response_model=AnalysisResponse)
async def analyze_url(req: UrlAnalysisRequest):
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")
    normalized = ContentNormalizer.normalize_url(req.url)
    res = await SecurityAnalyzer.analyze(normalized)
    await AnalysisRepository.save_analysis(res)
    return res


@router.post("/message", response_model=AnalysisResponse)
async def analyze_message(req: MessageAnalysisRequest):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Message text cannot be empty")
    normalized = ContentNormalizer.normalize_message(req.text, req.sender)
    res = await SecurityAnalyzer.analyze(normalized)
    await AnalysisRepository.save_analysis(res)
    return res


@router.post("/email", response_model=AnalysisResponse)
async def analyze_email(req: EmailAnalysisRequest):
    if req.raw_email and req.raw_email.strip():
        normalized = ContentNormalizer.normalize_raw_email(req.raw_email.strip())
    elif req.body and req.body.strip():
        normalized = ContentNormalizer.normalize_email(
            sender=req.sender.strip() if req.sender else "unknown-sender@unverified.org",
            subject=req.subject.strip() if req.subject else "",
            body=req.body.strip(),
            reply_to=req.reply_to.strip() if req.reply_to else None,
            headers=req.headers
        )
    else:
        raise HTTPException(status_code=400, detail="Please provide your full email message text")

    res = await SecurityAnalyzer.analyze(normalized)
    await AnalysisRepository.save_analysis(res)
    return res


@router.post("/qr", response_model=AnalysisResponse)
async def analyze_qr(req: QrAnalysisRequest):
    if not req.image_base64 and not req.decoded_payload:
        raise HTTPException(status_code=400, detail="Either QR image or decoded payload must be provided")
    normalized = ContentNormalizer.normalize_qr(req.image_base64, req.decoded_payload)
    res = await SecurityAnalyzer.analyze(normalized)
    await AnalysisRepository.save_analysis(res)
    return res


@router.post("/webpage", response_model=AnalysisResponse)
async def analyze_webpage(req: WebpageAnalysisRequest):
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="Target webpage URL cannot be empty")
    normalized = ContentNormalizer.normalize_webpage(req.url, req.html_content)
    res = await SecurityAnalyzer.analyze(normalized)
    await AnalysisRepository.save_analysis(res)
    return res


@router.post("/social", response_model=AnalysisResponse)
async def analyze_social(req: SocialAnalysisRequest):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Social message text cannot be empty")
    normalized = ContentNormalizer.normalize_social(req.text, req.platform or "generic")
    res = await SecurityAnalyzer.analyze(normalized)
    await AnalysisRepository.save_analysis(res)
    return res

