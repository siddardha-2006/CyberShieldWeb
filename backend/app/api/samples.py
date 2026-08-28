from fastapi import APIRouter

router = APIRouter(prefix="/samples", tags=["Test Samples"])

SAMPLE_PRESETS = [
    {
        "id": "bank_kyc_phish",
        "title": "Urgent Bank Account & KYC Freeze Phish",
        "type": "message",
        "severity_expected": "critical",
        "payload": {
            "text": "URGENT ALERT: Your State Bank account is temporarily blocked due to pending KYC verification. Click to update KYC and enter OTP within 24 hours: https://sbi-secure-kyc-update.com/login",
            "sender": "+18005550199"
        }
    },
    {
        "id": "legitimate_service",
        "title": "Legitimate Cloud Infrastructure Portal",
        "type": "url",
        "severity_expected": "safe",
        "payload": {
            "url": "https://docs.python.org/3/library/asyncio.html"
        }
    },
    {
        "id": "spoofed_executive_email",
        "title": "Executive BEC Wire Transfer Request",
        "type": "email",
        "severity_expected": "critical",
        "payload": {
            "sender": "ceo@corporate-tech.com",
            "reply_to": "ceo-direct-office@gmail.com",
            "subject": "CONFIDENTIAL: Immediate Payroll Wire Transfer Required",
            "body": "Are you at your desk? I need you to execute an urgent confidential wire transfer of $45,000 for an international vendor acquisition today before 4 PM. Do not discuss with the team until finalized.",
            "headers": {"received-spf": "fail", "authentication-results": "dkim=fail"}
        }
    },
    {
        "id": "suspicious_qr_payload",
        "title": "Malicious QR Code to Fake Gateway",
        "type": "qr",
        "severity_expected": "high_risk",
        "payload": {
            "decoded_payload": "http://192.168.1.105/auth/bank-verify-card.php?session=98214"
        }
    },
    {
        "id": "crypto_giveaway_scam",
        "title": "Crypto Double-Your-Money Social Media Scam",
        "type": "social",
        "severity_expected": "high_risk",
        "payload": {
            "text": "CLAIM FREE 5000 USDT! Binance celebration event is live. Send 0.1 BTC to verify your wallet address and receive 1.0 BTC immediately: https://binance-event-airdrop.live/claim",
            "platform": "telegram"
        }
    }
]


@router.get("")
async def get_presets():
    return {"samples": SAMPLE_PRESETS}

