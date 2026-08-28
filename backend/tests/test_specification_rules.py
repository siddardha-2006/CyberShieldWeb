import sys
import os
import asyncio

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.normalization.normalizer import ContentNormalizer
from app.detection.rules.engine import RuleEngine

test_scenarios = [
    # 1. Clean Verified Domain (Allowlist Protection)
    ("Clean Google Domain", ContentNormalizer.normalize_url("https://www.google.com/search?q=cybersecurity")),
    ("Clean Wikipedia Domain", ContentNormalizer.normalize_url("https://en.wikipedia.org/wiki/Phishing")),
    ("Clean GitHub Domain", ContentNormalizer.normalize_url("https://github.com/torvalds/linux")),

    # 2. Raw IP Address Host
    ("Raw IP Address Host", ContentNormalizer.normalize_url("http://185.220.101.5/portal/index.html")),

    # 3. Brand Impersonation & Typosquatting
    ("Apple iCloud Typosquat (br-icloud)", ContentNormalizer.normalize_url("http://br-icloud.com.br/login")),
    ("PayPal Phishing (.xyz TLD)", ContentNormalizer.normalize_url("https://paypal-verify-account.xyz/login")),

    # 4. Crypto Seed Phrase Theft
    ("Crypto Seed Phrase Harvest", ContentNormalizer.normalize_url("http://wallet-recovery.example.com/restore?seed=required")),

    # 5. Open Redirect & Obfuscation
    ("Open Redirect Parameter", ContentNormalizer.normalize_url("https://example.com/out?redirect=http://attacker.com")),

    # 6. Smishing / Urgency & Credential Combination (COMBO_001)
    ("Urgency + OTP SMS Lure", ContentNormalizer.normalize_message(
        "URGENT: Your bank account is suspended. Verify OTP within 24 hours to prevent account closure.",
        sender="+18005550199"
    )),

    # 7. Business Email Compromise (EMAIL_001, EMAIL_003, CRITICAL_003)
    ("Executive Wire BEC Email", ContentNormalizer.normalize_email(
        sender="ceo@corporate-tech.com",
        reply_to="hacker-mailbox@gmail.com",
        subject="CONFIDENTIAL: Urgent Wire Transfer Required",
        body="Are you at your desk? I need an urgent wire transfer of $45,000 processed immediately."
    ))
]

async def run_tests():
    print("==================================================================================================================")
    print("                  CYBERSHIELD SPECIFICATION-COMPLIANT RULE ENGINE VERIFICATION                   ")
    print("==================================================================================================================")
    print(f'{"SCENARIO":<35} | {"SCORE":<7} | {"SEVERITY":<10} | {"TRIGGERED RULES"}')
    print("------------------------------------------------------------------------------------------------------------------")

    for name, norm_data in test_scenarios:
        res = await RuleEngine.analyze(norm_data)
        rules_list = [e.code for e in res.evidence]
        rules_str = ', '.join(rules_list) if rules_list else "(None / Allowlisted)"
        severity = "CRITICAL" if res.score >= 80 else ("HIGH" if res.score >= 60 else ("MEDIUM" if res.score >= 40 else ("LOW" if res.score >= 20 else "SAFE")))
        print(f'{name:<35} | {res.score:<7} | {severity:<10} | {rules_str}')

    print("==================================================================================================================")

if __name__ == "__main__":
    asyncio.run(run_tests())

