import re
from typing import Dict, Any

class PrivacySanitizer:
    EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
    PHONE_REGEX = re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}')

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        """Mask emails, phone numbers, and potential sensitive values for storage."""
        if not text:
            return ""
        s = cls.EMAIL_REGEX.sub("[EMAIL]", text)
        s = cls.PHONE_REGEX.sub("[PHONE]", s)
        return s[:200]

