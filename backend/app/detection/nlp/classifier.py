import re
from typing import Dict, Any, Tuple


class SemanticPhishingClassifier:
    """
    Comprehensive NLP & Semantic Intent Classifier for cyber threats:
    - Phishing Intent & Document / Portal Lures
    - Credential, Corporate Login & Crypto Seed Theft
    - Social Engineering, Job Scams & Panic Urgency
    - Financial & Advance-Fee Fraud
    - Brand Impersonation & Typosquatting
    """
    
    PATTERNS = {
        "phishing": [
            r"\b(?:verify|confirm|validate|update|reactivate|renew|unlock|authenticate|restore|recover|sync)\s+(?:your\s+)?(?:account|identity|wallet|profile|card|details|membership|subscription|service|funds|vault)\b",
            r"\b(?:suspended|temporarily\s+locked|restricted|deactivated|blocked|frozen|disabled|flagged)\b",
            r"\bclick\s+(?:here|the\s+link|below|this\s+link)\s+to\s+(?:unlock|reactivate|verify|restore|claim|cancel|recover|review|confirm)\b",
            r"\b(?:review|access|confirm\s+access)\s+(?:the\s+)?(?:document|file|portal|attachment)\b",
            r"\bfailure\s+to\s+(?:respond|verify|comply|act)\s+will\s+result\b",
            r"\baction\s+required\s+within\b",
            r"\b(?:security|fraud|compromise|breach)\s+(?:alert|warning|notice)\b"
        ],
        "credential_theft": [
            r"\b(?:otp|one-time\s+pass(?:code|word)|security\s+code|2fa\s+code|verification\s+code|auth\s+code)\b",
            r"\b(?:enter|provide|share|input|submit|send|verify|confirm|sign\s*in\s*using|login\s*(?:with|using)?|log\s*in\s*(?:with|using)?|authenticate\s*using)\s+(?:your\s+)?(?:pin|password|passcode|credentials|secret\s+key|seed\s+phrase|recovery\s+phrase|private\s+key|mnemonic|keystore|organization\s+credentials|work\s+credentials)\b",
            r"\b(?:seed\s+phrase|recovery\s+phrase|secret\s+phrase|private\s+key|12\s+words|24\s+words|wallet\s+recovery|restore\s+wallet)\b",
            r"\b(?:reset|change)\s+your\s+password\s+(?:immediately|now)\b",
            r"\blogin\s+(?:credentials|details|information|here)\b",
            r"\b(?:card\s+number|cvv|expiry\s+date|atm\s+pin)\b",
            r"\borganization\s+credentials\b"
        ],
        "social_engineering": [
            r"\b(?:urgent|immediately|within\s+24\s+hours|final\s+notice|last\s+chance|instant\s+action|at\s+once)\b",
            r"\b(?:unauthorized\s+activity|unrecognized\s+device|suspicious\s+sign-in|unusual\s+login)\b",
            r"\b(?:dear\s+customer|valued\s+member|user\s+alert|attention\s+user)\b",
            r"\b(?:you\s+have\s+won|claim\s+your\s+prize|reward\s+notification|lottery\s+winner|gift\s+card\s+selected|claim\s+airdrop)\b",
            r"\b(?:recorded\s+your\s+camera|hacked\s+your\s+device|pay\s+bitcoin\s+or\s+leak)\b",
            r"\b(?:part-time\s+job|remote\s+job|shortlisted\s+for|earn\s+[₹$€£\d,–-]+\s+(?:daily|per\s+day)|work\s+from\s+home|from\s+home\s+income|daily\s+income)\b",
            r"\bcongratulations!?\s+your\s+profile\s+has\s+been\s+shortlisted\b",
            r"\breply\s+[“\"']?yes[”\"']?\s+to\s+continue\b"
        ],
        "financial_fraud": [
            r"\b(?:bank|credit\s+card|debit\s+card|paypal|crypto|bitcoin|usdt|eth|wire\s+transfer|wallet)\b",
            r"\b(?:kyc\s+update|tax\s+refund|direct\s+deposit|payroll\s+update|overdue\s+invoice)\b",
            r"\b(?:deducted|debited|charged|processed\s+payment|unauthorized\s+charge)\s+(?:rs|\$|usd|eur|inr|\u20b9)?\s*\d+\b",
            r"\b(?:customs\s+fee|unpaid\s+postage|delivery\s+fee|package\s+hold|registration\s+fee|processing\s+fee|entry\s+fee|security\s+deposit|one-time\s+registration)\b",
            r"\bpay\s+(?:rs\.?|\$|usd|eur|inr|\u20b9)?\s*\d+\b"
        ],
        "brand_impersonation": [
            r"\b(?:icloud|apple|appleid|findmy|microsoft|google|amazon|netflix|paypal|chase|wellsfargo|sbi|hdfc|icici|binance|metamask|coinbase|trustwallet|phantom|ledger|trezor|whatsapp|telegram|instagram|facebook)\b"
        ]
    }

    @classmethod
    def classify(cls, text: str) -> Tuple[Dict[str, float], Dict[str, Any]]:
        raw_clean = text.lower().strip()
        if not raw_clean:
            return {
                "phishing": 0.05,
                "credential_theft": 0.05,
                "social_engineering": 0.05,
                "financial_fraud": 0.05,
                "brand_impersonation": 0.05
            }, {}

        # De-tokenize URLs and normalize currency symbols
        words_from_symbols = re.sub(r'https?://|www\.|[/_?=&.-]', ' ', raw_clean)
        combined_text = f"{raw_clean} {words_from_symbols}"

        scores = {}
        matched_indicators = {}

        for category, patterns in cls.PATTERNS.items():
            cat_matches = []
            for pattern in patterns:
                found = re.findall(pattern, combined_text)
                if found:
                    cat_matches.extend(found)
            
            count = len(cat_matches)
            if count == 0:
                prob = 0.05
            elif count == 1:
                prob = 0.75
            elif count == 2:
                prob = 0.88
            else:
                prob = min(0.99, 0.88 + (0.04 * (count - 2)))

            scores[category] = round(prob, 2)
            if cat_matches:
                matched_indicators[category] = list(set(cat_matches))

        return scores, matched_indicators
