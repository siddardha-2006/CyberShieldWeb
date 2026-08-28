from app.core.security import generate_hmac_identifier

def compute_indicator_hmac(indicator: str) -> str:
    """Compute HMAC-SHA256 for privacy-preserving persistence."""
    return generate_hmac_identifier(indicator)

