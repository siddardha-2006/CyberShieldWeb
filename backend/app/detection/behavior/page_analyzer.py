import httpx
from typing import Dict, Any
from bs4 import BeautifulSoup
from app.detection.behavior.policy import BehavioralSecurityPolicy


class SandboxPageAnalyzer:
    """
    Lightweight sandboxed analyzer that inspects live network responses,
    redirect chains, form destination mutations, and credential inputs.
    """

    @classmethod
    async def inspect(cls, url: str) -> Dict[str, Any]:
        is_safe_to_visit, reason = BehavioralSecurityPolicy.validate_target_url(url)
        if not is_safe_to_visit:
            return {
                "blocked": True,
                "block_reason": reason,
                "redirect_count": 0,
                "has_login_form": False,
                "has_password_field": False,
                "has_otp_field": False,
                "has_payment_field": False,
                "cross_domain_submission": False
            }

        redirect_count = 0
        final_url = url
        has_password = False
        has_otp = False
        has_payment = False
        cross_domain_post = False

        try:
            timeout = httpx.Timeout(2.0, connect=1.5)
            async with httpx.AsyncClient(
                follow_redirects=True, 
                timeout=timeout, 
                headers={"User-Agent": "CyberShield-SecurityAnalyzer/1.0"}
            ) as client:
                resp = await client.get(url)
                redirect_count = len(resp.history)
                final_url = str(resp.url)
                
                soup = BeautifulSoup(resp.text, "html.parser")
                inputs = soup.find_all("input")
                types = [inp.get("type", "").lower() for inp in inputs]
                names = [inp.get("name", "").lower() for inp in inputs]

                has_password = "password" in types
                has_otp = any("otp" in n or "code" in n or "token" in n for n in names)
                has_payment = any("card" in n or "cvv" in n or "expiry" in n for n in names)

                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    if action.startswith("http") and not action.startswith(url[:20]):
                        cross_domain_post = True
        except Exception:
            # If target server is offline/unreachable or test mock
            pass

        return {
            "blocked": False,
            "redirect_count": redirect_count,
            "final_destination": final_url,
            "has_login_form": has_password,
            "has_password_field": has_password,
            "has_otp_field": has_otp,
            "has_payment_field": has_payment,
            "cross_domain_submission": cross_domain_post
        }
