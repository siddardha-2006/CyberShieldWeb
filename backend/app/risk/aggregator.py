from typing import Dict, List, Tuple
from app.schemas.analysis import EngineResult, EvidenceItem, RiskAssessment
from app.risk.categories import RiskCategoryManager
from app.risk.confidence import ConfidenceCalculator


class RiskAggregator:
    # Standard base weights defined in architecture specification
    BASE_WEIGHTS = {
        "rules": 0.25,
        "nlp": 0.30,
        "threat_intelligence": 0.25,
        "behavior": 0.20
    }

    @classmethod
    def aggregate(cls, engine_results: Dict[str, EngineResult]) -> Tuple[RiskAssessment, List[EvidenceItem]]:
        all_evidence: List[EvidenceItem] = []
        scores_by_engine = {}

        # Collect active engines that completed successfully
        active_weights = {}
        weighted_score_sum = 0.0

        for engine_name, res in engine_results.items():
            scores_by_engine[engine_name] = res.score
            if res.evidence:
                all_evidence.extend(res.evidence)

            if res.status == "completed":
                weight = cls.BASE_WEIGHTS.get(engine_name, 0.25)
                active_weights[engine_name] = weight

        # Re-normalize weights across contributing engines
        total_active_weight = sum(active_weights.values())
        
        if total_active_weight > 0:
            for engine_name, base_w in active_weights.items():
                normalized_w = base_w / total_active_weight
                weighted_score_sum += engine_results[engine_name].score * normalized_w
            final_risk_score = int(round(weighted_score_sum))
        else:
            final_risk_score = 0

        # Defense-in-depth single-engine threat floor:
        # If any single engine detects strong malicious indicators (e.g. Rule score >= 50 or NLP score >= 60),
        # prevent other inactive or zero-score engines from excessively diluting the real danger.
        completed_scores = [res.score for res in engine_results.values() if res.status == "completed"]
        if completed_scores:
            max_engine_score = max(completed_scores)
            if max_engine_score >= 60:
                final_risk_score = max(final_risk_score, int(max_engine_score * 0.85))
            elif max_engine_score >= 40:
                final_risk_score = max(final_risk_score, int(max_engine_score * 0.75))

        # Critical threat override: if Threat Intel or multiple engines detected critical findings
        critical_evidence_count = sum(1 for e in all_evidence if e.severity == "critical")
        if critical_evidence_count >= 2 and final_risk_score < 80:
            final_risk_score = min(100, max(final_risk_score, 82 + (critical_evidence_count * 3)))

        # Final bounds check
        final_risk_score = max(0, min(100, final_risk_score))

        # Severity & Category
        severity = RiskCategoryManager.get_severity(final_risk_score)
        category, secondary_cats = RiskCategoryManager.resolve_threat_category(scores_by_engine, all_evidence)

        # Confidence
        confidence = ConfidenceCalculator.calculate(engine_results)

        # Recommended Safe Action
        if severity == "safe":
            rec_action = "ALLOW"
            action_details = "No malicious indicators detected. Standard caution advised when browsing unknown sources."
        elif severity == "suspicious":
            rec_action = "WARN"
            action_details = "Unusual patterns or elevated risk detected. Verify the destination / sender independently before proceeding."
        elif severity == "high_risk":
            rec_action = "DO_NOT_INTERACT"
            action_details = "Strong indicators of phishing or fraud detected. Do not click links, input passwords, or share any personal info."
        else: # critical
            rec_action = "REPORT"
            action_details = "Confirmed malicious threat vector identified. Close immediately, block sender, and file a security incident report."

        assessment = RiskAssessment(
            risk_score=final_risk_score,
            confidence=confidence,
            severity=severity,
            category=category,
            secondary_categories=secondary_cats,
            recommended_action=rec_action,
            action_details=action_details
        )

        return assessment, all_evidence
