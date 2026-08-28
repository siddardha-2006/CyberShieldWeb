import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_endpoints():
    print("Testing /api/v1/analyze/email with raw email:")
    email_text = """Hello,

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

    res = client.post("/api/v1/analyze/email", json={"raw_email": email_text})
    print("Email Status Code:", res.status_code)
    if res.status_code != 200:
        print("Email Response Error:", res.text)
    else:
        print("Email Category:", res.json().get("assessment", {}).get("category"))
        print("Email Risk Score:", res.json().get("assessment", {}).get("risk_score"))

    print("\nTesting /api/v1/analyze/url:")
    res_url = client.post("/api/v1/analyze/url", json={"url": "https://google.com"})
    print("URL Status Code:", res_url.status_code)
    if res_url.status_code != 200:
        print("URL Response Error:", res_url.text)

    print("\nTesting /api/v1/analyze/social:")
    res_soc = client.post("/api/v1/analyze/social", json={"text": "Earn money from home ₹5000", "platform": "telegram"})
    print("Social Status Code:", res_soc.status_code)
    if res_soc.status_code != 200:
        print("Social Response Error:", res_soc.text)

if __name__ == "__main__":
    test_endpoints()
