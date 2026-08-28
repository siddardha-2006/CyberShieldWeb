"""
CyberShield Rule Scorer & Evidence Generator
--------------------------------------------
Calculates the final risk score, applies severity escalation thresholds,
and formats explainable rule findings per specification (§5, §23, §24, §25, §26).
"""

from typing import List, Literal, Tuple
from app.detection.rules.models import TriggeredRule, RuleEvaluationResult


class RuleScorer:
    @staticmethod
    def calculate_classification(score: int) -> Literal["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        """Map score to classification per §5."""
        if score <= 19:
            return "SAFE"
        elif score <= 39:
            return "LOW"
        elif score <= 59:
            return "MEDIUM"
        elif score <= 79:
            return "HIGH"
        else:
            return "CRITICAL"

    @classmethod
    def score(
        cls, 
        triggered_rules: List[TriggeredRule], 
        is_critical_escalated: bool = False
    ) -> RuleEvaluationResult:
        raw_points = sum(r.points for r in triggered_rules)

        # Critical Escalation (§19, §24)
        if is_critical_escalated:
            final_score = min(100, max(80, raw_points))
        else:
            final_score = min(100, max(0, raw_points))

        classification = cls.calculate_classification(final_score)

        # Confidence calculation based on evidence volume
        if len(triggered_rules) == 0:
            confidence = 0.88
        else:
            confidence = min(0.98, 0.75 + (0.05 * len(triggered_rules)))

        # Generate human-readable explanation and recommendations
        indicators = [r.title for r in triggered_rules]
        if classification == "CRITICAL":
            explanation = "Multiple high-confidence phishing and security threats were correlated."
            recommendation = "Do not open the link, enter authentication credentials, or transfer funds."
        elif classification == "HIGH":
            explanation = "Significant suspicious security indicators were detected."
            recommendation = "Exercise extreme caution; verify identity through official channels."
        elif classification == "MEDIUM":
            explanation = "Elevated risk signals detected. Proceed with caution."
            recommendation = "Double-check sender identity and domain spelling before interacting."
        elif classification == "LOW":
            explanation = "Minor or contextual risk factors observed."
            recommendation = "Standard caution recommended."
        else:
            explanation = "No malicious indicators or threats detected by security rules."
            recommendation = "Content appears clean and safe to interact with."

        return RuleEvaluationResult(
            risk_score=final_score,
            classification=classification,
            confidence=round(confidence, 2),
            triggered_rules=triggered_rules,
            indicators=indicators,
            explanation=explanation,
            recommendation=recommendation,
            engine="rule_engine",
            rule_version="2.0.0"
        )

