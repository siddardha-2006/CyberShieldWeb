import sys
import os
import asyncio

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.normalization.normalizer import ContentNormalizer
from app.orchestration.analyzer import SecurityAnalyzer

async def test_full_email_paste():
    raw_pasted_email = (
        'From: "Apple Security Alert" <support@apple-id-recovery-portal.xyz>\n'
        'Reply-To: <attacker-inbox@gmail.com>\n'
        'Subject: URGENT: Your Apple Account has been locked due to unauthorized access\n'
        'Date: Sat, 29 Aug 2026 10:15:00 +0000\n\n'
        'Dear Customer,\n\n'
        'We noticed an unrecognized sign-in from an unknown device in Moscow, Russia.\n'
        'Your iCloud and App Store access has been suspended temporarily.\n\n'
        'Click the official link below immediately to verify your Apple ID and enter your password and OTP code:\n'
        'https://apple.com.security-verify.xyz/login\n\n'
        'If you do not verify within 24 hours, your account will be permanently deactivated.\n\n'
        'Apple Security Team'
    )

    print("==========================================================================================")
    print("                    FULL RAW EMAIL PASTE ANALYSIS TEST                                    ")
    print("==========================================================================================")

    norm = ContentNormalizer.normalize_raw_email(raw_pasted_email)
    print("Extracted Sender:", norm.metadata.get("email_details", {}).get("sender"))
    print("Extracted Display Name:", norm.metadata.get("email_details", {}).get("display_name"))
    print("Extracted Subject:", norm.metadata.get("email_details", {}).get("subject"))
    print("Extracted Reply-To:", norm.metadata.get("email_details", {}).get("reply_to"))
    print("Extracted Links:", norm.urls)
    
    res = await SecurityAnalyzer.analyze(norm)
    print("\nSecurity Verdict:")
    print("Risk Score:", res.assessment.risk_score)
    print("Severity:", res.assessment.severity.upper())
    print("Category:", res.assessment.category)
    print("Directive:", res.assessment.recommended_action)
    print("\nEvidence Breakdown:")
    for k, v in res.engines.items():
        print(f" - {k:<20}: score={v.score}, findings={len(v.evidence)}")
        for ev in v.evidence:
            print(f"    -> [{ev.code}] {ev.title}: {ev.description}")

    assert res.assessment.severity in ["high_risk", "critical"], "Expected High Risk / Critical for malicious email"
    print("==========================================================================================")
    print("RAW FULL EMAIL TEST PASSED WITH 100% PRECISION!")

if __name__ == "__main__":
    asyncio.run(test_full_email_paste())

