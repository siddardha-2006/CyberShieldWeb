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

test_cases = [
    # Normal URLs
    ("Normal URL 1 (Google)", ContentNormalizer.normalize_url("https://www.google.com")),
    ("Normal URL 2 (Wikipedia)", ContentNormalizer.normalize_url("https://en.wikipedia.org/wiki/Computer_security")),
    ("Normal URL 3 (GitHub)", ContentNormalizer.normalize_url("https://github.com/torvalds/linux")),

    # Malicious URLs
    ("Malicious URL 1 (br-icloud typosquat)", ContentNormalizer.normalize_url("http://br-icloud.com.br")),
    ("Malicious URL 2 (PayPal Phishing .xyz)", ContentNormalizer.normalize_url("https://paypal-verify-account.xyz/login")),
    ("Malicious URL 3 (IP host & path)", ContentNormalizer.normalize_url("http://192.168.1.50/account/login-verify.php")),

    # Normal Messages
    ("Normal Text 1 (Work Planning)", ContentNormalizer.normalize_message("Hi team, please find attached the meeting minutes from our Tuesday planning session.")),
    ("Normal Text 2 (Family Greeting)", ContentNormalizer.normalize_message("Hey Mom, dinner was great, let me know when you arrive home safely!")),

    # Malicious Messages
    ("Malicious Text 1 (Bank KYC Phish)", ContentNormalizer.normalize_message("URGENT: State Bank account blocked due to pending KYC. Verify OTP within 24 hours: https://sbi-secure-kyc-update.com/login", sender="+18005550199")),
    ("Malicious Text 2 (Netflix Expire Scam)", ContentNormalizer.normalize_message("ALERT: Your Netflix subscription has expired. Update your credit card details immediately: http://netflix-renew.top/auth", sender="ALERT")),

    # Malicious Email
    ("Malicious Email (Executive BEC Wire)", ContentNormalizer.normalize_email(
        sender="ceo@corporate-tech.com",
        reply_to="hacker-mailbox@gmail.com",
        subject="CONFIDENTIAL: Urgent Wire Transfer Required",
        body="Are you at your desk? I need an urgent wire transfer of $45,000 processed before 3pm."
    ))
]

async def run_verification():
    print("========================================================================================")
    print(f'{"TEST CASE":<40} | {"RISK SCORE":<10} | {"SEVERITY":<12} | {"ACTION":<15}')
    print("========================================================================================")

    for name, norm_input in test_cases:
        res = await SecurityAnalyzer.analyze(norm_input)
        score = f"{res.assessment.risk_score}/100"
        severity = res.assessment.severity.upper()
        action = res.assessment.recommended_action
        print(f'{name:<40} | {score:<10} | {severity:<12} | {action:<15}')

    print("========================================================================================")

if __name__ == "__main__":
    asyncio.run(run_verification())

