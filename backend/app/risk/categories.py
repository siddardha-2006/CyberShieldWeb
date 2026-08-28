from typing import Literal, Tuple


class RiskCategoryManager:
    """
    Categorizes numerical risk scores (0-100) into severity bands
    and maps dominant evidence categories.
    """

    @classmethod
    def get_severity(cls, score: int) -> Literal["safe", "suspicious", "high_risk", "critical"]:
        if score < 30:
            return "safe"
        elif score < 60:
            return "suspicious"
        elif score < 80:
            return "high_risk"
        else:
            return "critical"

    @classmethod
    def resolve_threat_category(cls, scores_by_engine: dict, evidence_list: list) -> Tuple[str, list]:
        if not evidence_list:
            return "Benign / Safe Content", []

        # PhishTank priority override:
        has_phishtank = any(
            "phishtank" in getattr(e, "code", "").lower() or 
            "phishtank" in getattr(e, "title", "").lower() or 
            "phishtank" in str(getattr(e, "metadata", {})).lower()
            for e in evidence_list
        )
        if has_phishtank:
            return "PhishTank Verified Phishing Threat", ["Global Threat Feed Blacklist", "Credential Harvesting"]

        category_weights = {}
        for ev in evidence_list:
            cat = str(getattr(ev, "category", "general")).lower()
            w = getattr(ev, "weight", 10)
            category_weights[cat] = category_weights.get(cat, 0) + w

        sorted_cats = sorted(category_weights.items(), key=lambda x: x[1], reverse=True)
        primary_cat_raw = sorted_cats[0][0].lower() if sorted_cats else "general"

        friendly_names = {
            "phishing": "Phishing & Deceptive Landing Page",
            "credential_theft": "Credential & OTP Harvesting",
            "social_engineering": "Social Engineering & Coercion",
            "financial_fraud": "Financial / Banking Fraud",
            "malware": "Malware / Malicious Payload Distribution",
            "reputation": "Known Malicious Domain / IP",
            "brand_impersonation": "Brand Impersonation & Spoofing",
            "suspicious_infrastructure": "Suspicious Host Infrastructure",
            "impersonation": "Sender Spoofing & BEC Attempt",
            "evasion": "Scanner Evasion Redirection",
            "exfiltration": "Cross-Origin Credential Exfiltration",
            "correlation": "Advance-Fee & Multi-Vector Social Engineering Scam",
            "text_social_engineering": "Social Engineering & Lure Fraud",
            "text_financial": "Financial & Advance-Fee Fraud",
            "text_credential": "Credential & Token Harvesting"
        }

        primary = friendly_names.get(primary_cat_raw, primary_cat_raw.replace("_", " ").title())
        secondary = [friendly_names.get(c[0], c[0].replace("_", " ").title()) for c in sorted_cats[1:4]]
        return primary, secondary
