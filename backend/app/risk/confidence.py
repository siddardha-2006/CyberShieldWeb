from typing import Dict
from app.schemas.analysis import EngineResult


class ConfidenceCalculator:
    """
    Computes overall confidence score (0.00 to 1.00) independent of the risk score.
    Higher engine consensus and multi-source corroboration increase confidence.
    """

    @classmethod
    def calculate(cls, engine_results: Dict[str, EngineResult]) -> float:
        valid_engines = [
            res for res in engine_results.values() 
            if res.status == "completed"
        ]

        if not valid_engines:
            return 0.50

        # Average individual engine confidences
        avg_confidence = sum(e.confidence for e in valid_engines) / len(valid_engines)
        
        # Corroboration boost: if >=2 engines flagged significant risk (>40) or <=20
        elevated_risk_engines = sum(1 for e in valid_engines if e.score >= 40)
        if elevated_risk_engines >= 2:
            avg_confidence = min(0.99, avg_confidence + 0.05)

        return round(avg_confidence, 2)

