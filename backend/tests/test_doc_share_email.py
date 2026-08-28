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

async def test_email():
    text = """Hello,

A document associated with your account was recently shared with you through the organization’s document portal.

**Document:** Q3_Account_Review.pdf
**Shared by:** Finance Operations
**Access status:** Awaiting confirmation

You can review the document and confirm access using the secure document portal below:

`https://document-access.example.test/confirm`

For verification, you may be asked to sign in using your organization credentials.

If you were not expecting this document, please do not forward this message. Contact the service desk through your usual internal channel.

Regards,
Document Services
Automated Notification System

**Sender:** `notifications@example.test`
**Reply-To:** `document-support@example.test`"""

    norm = ContentNormalizer.normalize_raw_email(text)
    res = await SecurityAnalyzer.analyze(norm)
    print("====================================================================")
    print("                    DOC SHARE EMAIL ANALYSIS                        ")
    print("====================================================================")
    print("Extracted Sender:", norm.metadata.get("email_details", {}).get("sender"))
    print("Extracted Subject:", norm.metadata.get("email_details", {}).get("subject"))
    print("Extracted URLs:", norm.urls)
    print("\nSecurity Verdict:")
    print("Risk Score:", res.assessment.risk_score)
    print("Severity:", res.assessment.severity)
    print("Category:", res.assessment.category)
    print("Explainability Summary:", res.explainability.summary)
    print("\nEngine Breakdown:")
    for k, v in res.engines.items():
        print(f" - {k:<20}: score={v.score}, findings={len(v.evidence)}")
        for ev in v.evidence:
            print(f"    -> [{ev.code}] {ev.title}: {ev.description}")
    print("====================================================================")

if __name__ == "__main__":
    asyncio.run(test_email())

