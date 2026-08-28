import logging
import sys
import re

class PrivacyScrubbingFormatter(logging.Formatter):
    """
    Formatter that strips sensitive indicators (emails, tokens, passwords, OTPs)
    to enforce privacy-by-design logging policies.
    """
    EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
    OTP_REGEX = re.compile(r'\b\d{4,8}\b')
    TOKEN_REGEX = re.compile(r'(?:Bearer\s+|jwt=|token=)[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', re.IGNORECASE)

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        msg = self.TOKEN_REGEX.sub("[REDACTED_TOKEN]", msg)
        msg = self.EMAIL_REGEX.sub("[REDACTED_EMAIL]", msg)
        return msg


def setup_logger(name: str = "cybershield") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            PrivacyScrubbingFormatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        )
        logger.addHandler(handler)
    return logger


logger = setup_logger()

