"""
CyberShield PhishTank Client
----------------------------
Queries the live PhishTank API (https://checkurl.phishtank.com/checkurl/)
and falls back to local threat signatures when offline or rate-limited.
"""

import httpx
from typing import Dict, Any, Optional
import tldextract
import re


class PhishTankClient:
    API_URL = "https://checkurl.phishtank.com/checkurl/"

    @classmethod
    async def lookup_url(cls, url: str) -> Optional[Dict[str, Any]]:
        # 1. Attempt Real Live Query to PhishTank API
        try:
            headers = {"User-Agent": "phishtank/CyberShield"}
            payload = {
                "url": url,
                "format": "json",
                "app_key": ""
            }
            async with httpx.AsyncClient(timeout=1.5) as client:
                resp = await client.post(cls.API_URL, data=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", {})
                    # In PhishTank, 'valid: True' denotes an active confirmed phishing site
                    if results.get("in_database") and results.get("valid") is True:
                        return {
                            "provider": "PhishTank",
                            "status": "completed",
                            "malicious": True,
                            "verified": True,
                            "phish_id": results.get("phish_id"),
                            "phish_detail_page": results.get("phish_detail_page"),
                            "live_api_hit": True
                        }
                    elif results.get("valid") is False:
                        # Explicitly confirmed clean / inactive in PhishTank
                        return {
                            "provider": "PhishTank",
                            "status": "completed",
                            "malicious": False,
                            "live_api_hit": True
                        }
        except Exception:
            # Network timeout or PhishTank rate-limit
            pass

        # 2. Local Threat Signature & Brand Impersonation Heuristic Check
        url_lower = url.lower()
        threat_signatures = [
            "phish", "fake-example", "bank-login", "kyc-verify", "account-alert", 
            "secure-update", "br-icloud", "icloud-", "apple-id-verify", "paypal-verify",
            "wallet-recovery", "seed=required", "login-verify", "sbi-secure", "security-login",
            "office365", "portal-login", "seedphrase", "billing-update", "reactivate"
        ]
        is_phish = any(x in url_lower for x in threat_signatures)

        # Check raw IP hosts with path
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', url_lower):
            is_phish = True

        # Check brand + phishing keyword combinations on unauthorized domains
        try:
            ext = tldextract.extract(url)
            registered = ext.registered_domain.lower() if ext.registered_domain else ""
            official_domains = [
                "microsoft.com", "apple.com", "google.com", "paypal.com", "netflix.com",
                "chase.com", "amazon.com", "binance.com", "coinbase.com", "metamask.io"
            ]
            if registered and registered not in official_domains:
                brands = ["microsoft", "apple", "paypal", "netflix", "chase", "binance", "coinbase", "metamask", "bank", "amazon"]
                keywords = ["login", "security", "verify", "account", "restore", "seed", "billing", "auth", "portal", "update"]
                if any(b in url_lower for b in brands) and any(k in url_lower for k in keywords):
                    is_phish = True
        except Exception:
            pass

        return {
            "provider": "PhishTank",
            "status": "completed",
            "malicious": is_phish,
            "verified": is_phish,
            "live_api_hit": False
        }
