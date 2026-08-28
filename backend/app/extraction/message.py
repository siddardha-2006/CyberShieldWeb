import re
from typing import Dict, Any, List, Optional
from urlextract import URLExtract
import tldextract


class MessageExtractor:
    url_extractor = URLExtract()
    
    PHONE_REGEX = re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}')
    EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
    
    # Heuristic indicator keyword groups
    URGENCY_KEYWORDS = [
        "urgent", "immediately", "suspended", "blocked", "warning", "action required", 
        "24 hours", "locked", "expire", "unauthorized", "alert", "security alert"
    ]
    FINANCIAL_KEYWORDS = [
        "bank", "account", "credit card", "debit card", "payment", "crypto", "bitcoin", 
        "kyc", "tax refund", "prize", "winner", "lottery", "cash reward", "wire transfer", "inr", "usd"
    ]
    CREDENTIAL_KEYWORDS = [
        "otp", "one-time password", "pin", "password", "verification code", "verify your account", 
        "login", "sign in", "reset password", "credentials"
    ]

    @classmethod
    def extract(cls, text: str, sender: Optional[str] = None) -> Dict[str, Any]:
        raw_text = text.strip()
        lower_text = raw_text.lower()
        
        # Extract URLs
        try:
            urls = cls.url_extractor.find_urls(raw_text)
        except Exception:
            urls = []
            
        domains = []
        for u in urls:
            try:
                ext = tldextract.extract(u)
                if ext.registered_domain:
                    domains.append(ext.registered_domain)
            except Exception:
                pass
                
        # Extract emails
        emails = cls.EMAIL_REGEX.findall(raw_text)
        
        # Extract phone numbers
        phones = cls.PHONE_REGEX.findall(raw_text)
        if sender and sender not in phones:
            phones.append(sender)
            
        # Match keywords
        matched_urgency = [kw for kw in cls.URGENCY_KEYWORDS if kw in lower_text]
        matched_financial = [kw for kw in cls.FINANCIAL_KEYWORDS if kw in lower_text]
        matched_credentials = [kw for kw in cls.CREDENTIAL_KEYWORDS if kw in lower_text]
        
        return {
            "raw_text": raw_text,
            "sender": sender,
            "urls": urls,
            "domains": list(set(domains)),
            "emails": list(set(emails)),
            "phones": list(set(phones)),
            "indicators": {
                "urgency_count": len(matched_urgency),
                "urgency_keywords": matched_urgency,
                "financial_count": len(matched_financial),
                "financial_keywords": matched_financial,
                "credential_count": len(matched_credentials),
                "credential_keywords": matched_credentials,
                "has_otp_request": "otp" in lower_text or "verification code" in lower_text or "pin" in lower_text,
                "has_link": len(urls) > 0
            }
        }

