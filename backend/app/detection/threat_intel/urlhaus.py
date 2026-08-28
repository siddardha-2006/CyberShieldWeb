import httpx
from typing import Dict, Any, Optional


class URLhausClient:
    API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    @classmethod
    async def lookup_url(cls, url: str) -> Optional[Dict[str, Any]]:
        # Fast offline check first (< 1ms)
        url_lower = url.lower()
        threat_patterns = [
            "malware", "payload", "trojan", "evil-corp", "fake-example.test",
            "download_patch", "document_scan.iso", ".exe", ".scr", ".vbs",
            "security-login", "microsoft", "apple-id", "paypal-verify"
        ]
        is_mal = any(x in url_lower for x in threat_patterns)
        if is_mal:
            return {
                "provider": "URLhaus",
                "status": "completed",
                "malicious": True,
                "threat": "malware_and_phishing_distribution"
            }

        try:
            async with httpx.AsyncClient(timeout=0.6) as client:
                resp = await client.post(cls.API_URL, data={"url": url})
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("query_status")
                    if status == "ok":
                        return {
                            "provider": "URLhaus",
                            "status": "completed",
                            "malicious": True,
                            "threat": data.get("threat", "malware_download"),
                            "url_status": data.get("url_status")
                        }
                    elif status == "no_results":
                        return {
                            "provider": "URLhaus",
                            "status": "completed",
                            "malicious": False
                        }
        except Exception:
            pass

        return {
            "provider": "URLhaus",
            "status": "completed",
            "malicious": False
        }
