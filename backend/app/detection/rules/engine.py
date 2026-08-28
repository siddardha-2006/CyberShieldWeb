"""
CyberShield Rule Engine
-----------------------
The decision and correlation layer of CyberShield.
Consumes normalized indicators and applies deterministic security rules,
multi-signal correlation, duplicate suppression, and critical escalation.
"""

import time
from typing import List
from app.schemas.analysis import NormalizedInput, EngineResult, EvidenceItem
from app.detection.rules.evaluator import RuleEvaluator
from app.detection.rules.scorer import RuleScorer


class RuleEngine:
    name = "rules"

    @classmethod
    async def analyze(cls, data: NormalizedInput) -> EngineResult:
        start_time = time.perf_counter()

        # 1. Evaluate rules & correlation combinations
        triggered_rules, is_critical_escalated = RuleEvaluator.evaluate(data)

        # 2. Score and classify
        result = RuleScorer.score(triggered_rules, is_critical_escalated)

        # 3. Convert triggered rules to standard EvidenceItem objects
        evidence_items: List[EvidenceItem] = []
        for r in result.triggered_rules:
            evidence_items.append(
                EvidenceItem(
                    engine="rules",
                    code=r.rule_id,
                    title=r.title,
                    description=r.description,
                    weight=r.points,
                    severity=r.severity,
                    category=r.category,
                    metadata=r.metadata
                )
            )

        latency = int((time.perf_counter() - start_time) * 1000)

        return EngineResult(
            engine="rules",
            status="completed",
            score=result.risk_score,
            confidence=result.confidence,
            evidence=evidence_items,
            latency_ms=latency
        )
