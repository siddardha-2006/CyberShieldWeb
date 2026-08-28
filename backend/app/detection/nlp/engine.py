import os
import re
import time
from typing import List, Optional
from app.schemas.analysis import NormalizedInput, EngineResult, EvidenceItem
from app.detection.nlp.classifier import SemanticPhishingClassifier

try:
    import joblib
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "phishing_classifier.joblib")
    if os.path.exists(MODEL_PATH):
        ml_model = joblib.load(MODEL_PATH)
    else:
        ml_model = None
except Exception:
    ml_model = None

TOP_BENIGN_ROOTS = {
    "google.com", "google.co.in", "google.co.uk", "google.com.br", "gmail.com", "youtube.com",
    "wikipedia.org", "wikimedia.org", "github.com", "microsoft.com", "apple.com", "icloud.com",
    "amazon.com", "amazon.in", "facebook.com", "instagram.com", "whatsapp.com", "netflix.com"
}

def extract_clean_tokens(text: str) -> str:
    t = text.strip().lower()
    t = re.sub(r'^https?://', '', t)
    t = re.sub(r'^www\.', '', t)
    tokens = re.split(r'[/_?=&.-]', t)
    meaningful = [tok for tok in tokens if len(tok) > 1 and tok not in ['com', 'org', 'net', 'html', 'php', 'htm', 'index', 'asp']]
    return ' '.join(meaningful)


class NlpEngine:
    name = "nlp"

    @classmethod
    async def analyze(cls, data: NormalizedInput) -> EngineResult:
        start_time = time.perf_counter()
        
        # Determine text content to analyze
        text_to_analyze = data.text
        if not text_to_analyze and data.urls:
            text_to_analyze = " ".join(data.urls)

        if not text_to_analyze.strip():
            latency = int((time.perf_counter() - start_time) * 1000)
            return EngineResult(
                engine="nlp",
                status="not_applicable",
                score=0,
                confidence=0.0,
                evidence=[],
                latency_ms=latency
            )

        # 1. Semantic intent analysis for messages / emails / paths
        classifications, matched_features = SemanticPhishingClassifier.classify(text_to_analyze)
        
        # 2. Machine Learning trained model inference (for URLs and text)
        ml_phish_prob = None
        if ml_model is not None:
            try:
                # Check for verified benign root domains
                is_clean_root = False
                if data.input_type in ["url", "qr"] and "url_details" in data.metadata:
                    reg_domain = data.metadata["url_details"].get("registered_domain", "")
                    is_brand_imp = data.metadata["url_details"].get("is_brand_impersonation", False)
                    if reg_domain in TOP_BENIGN_ROOTS and not is_brand_imp:
                        is_clean_root = True

                if is_clean_root:
                    ml_phish_prob = 0.02
                else:
                    tokens = extract_clean_tokens(text_to_analyze)
                    probs = ml_model.predict_proba([tokens])[0]
                    ml_phish_prob = float(probs[1])
            except Exception:
                pass

        # Calculate overall threat score
        intent_probs = [
            classifications.get("phishing", 0.0),
            classifications.get("credential_theft", 0.0),
            classifications.get("social_engineering", 0.0),
            classifications.get("financial_fraud", 0.0)
        ]
        if ml_phish_prob is not None:
            intent_probs.append(ml_phish_prob)

        max_intent_prob = max(intent_probs)

        if max_intent_prob <= 0.15:
            final_score = int(max_intent_prob * 100)
        else:
            weighted_score = int(
                classifications.get("phishing", 0.0) * 35 +
                classifications.get("credential_theft", 0.0) * 30 +
                classifications.get("social_engineering", 0.0) * 20 +
                ((ml_phish_prob or 0.0) * 30)
            )
            if classifications.get("brand_impersonation", 0.0) >= 0.60:
                weighted_score = min(100, weighted_score + 15)

            final_score = min(100, max(int(max_intent_prob * 100), weighted_score))

        evidence: List[EvidenceItem] = []

        if classifications.get("phishing", 0) >= 0.60 or (ml_phish_prob and ml_phish_prob >= 0.70):
            evidence.append(
                EvidenceItem(
                    engine="nlp",
                    code="NLP_PHISHING_INTENT",
                    title="Semantic & ML Phishing Intent Detected",
                    description=f"Trained NLP & ML models indicate phishing patterns or credential harvesting intent (ML Confidence: {int((ml_phish_prob or classifications['phishing'])*100)}%).",
                    weight=35,
                    severity="high" if max_intent_prob < 0.85 else "critical",
                    category="phishing",
                    metadata={"probability": round(max_intent_prob, 2), "ml_prediction": ml_phish_prob}
                )
            )

        if classifications.get("credential_theft", 0) >= 0.60:
            evidence.append(
                EvidenceItem(
                    engine="nlp",
                    code="NLP_CREDENTIAL_SOLICITATION",
                    title="Credential / OTP Harvesting Intent",
                    description="Text attempts to solicit credentials, one-time passwords, secret seed phrases, or PINs.",
                    weight=35,
                    severity="critical",
                    category="credential_theft",
                    metadata={"probability": classifications["credential_theft"]}
                )
            )

        if classifications.get("social_engineering", 0) >= 0.60:
            evidence.append(
                EvidenceItem(
                    engine="nlp",
                    code="NLP_URGENCY_MANIPULATION",
                    title="Artificial Urgency & Coercive Pressure",
                    description="Text employs psychological pressure tactics (threat of suspension, artificial deadlines) to force hasty action.",
                    weight=25,
                    severity="high",
                    category="social_engineering",
                    metadata={"probability": classifications["social_engineering"]}
                )
            )

        confidence = round(min(0.98, 0.80 + (0.05 * len(evidence))), 2) if evidence else 0.88
        latency = int((time.perf_counter() - start_time) * 1000)

        return EngineResult(
            engine="nlp",
            status="completed",
            score=final_score,
            confidence=confidence,
            evidence=evidence,
            classifications=classifications,
            latency_ms=latency
        )
