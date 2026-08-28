import asyncio
import time
from datetime import datetime, timezone
from typing import Dict, Any
from app.schemas.analysis import NormalizedInput, AnalysisResponse, EngineResult
from app.core.config import settings
from app.core.logging import logger

# Detection Engines
from app.detection.rules.engine import RuleEngine
from app.detection.nlp.engine import NlpEngine
from app.detection.threat_intel.engine import ThreatIntelligenceEngine
from app.detection.behavior.engine import BehavioralAnalysisEngine

from app.orchestration.parallel import ParallelExecutor
from app.risk.aggregator import RiskAggregator
from app.explainability.explanations import ExplainabilityGenerator


class SecurityAnalyzer:
    """
    Central orchestration coordinator:
    1. Launches the 4 detection engines concurrently
    2. Collects heterogeneous evidence
    3. Fuses multi-engine telemetry
    4. Computes risk, confidence, explainability, and safe action recommendations
    """

    @classmethod
    async def analyze(cls, normalized_data: NormalizedInput) -> AnalysisResponse:
        overall_start = time.perf_counter()
        analysis_id = normalized_data.analysis_id

        logger.info(f"Starting parallel analysis id={analysis_id} input_type={normalized_data.input_type}")

        # Launch all 4 detection engines concurrently
        tasks = [
            ParallelExecutor.run_with_timeout(
                "rules", 
                RuleEngine.analyze(normalized_data), 
                settings.RULE_ENGINE_TIMEOUT
            ),
            ParallelExecutor.run_with_timeout(
                "nlp", 
                NlpEngine.analyze(normalized_data), 
                settings.NLP_ENGINE_TIMEOUT
            ),
            ParallelExecutor.run_with_timeout(
                "threat_intelligence", 
                ThreatIntelligenceEngine.analyze(normalized_data), 
                settings.THREAT_INTEL_TIMEOUT
            ),
            ParallelExecutor.run_with_timeout(
                "behavior", 
                BehavioralAnalysisEngine.analyze(normalized_data), 
                settings.BEHAVIOR_TIMEOUT
            )
        ]

        engine_outputs = await asyncio.gather(*tasks)

        engines_dict: Dict[str, EngineResult] = {
            "rules": engine_outputs[0],
            "nlp": engine_outputs[1],
            "threat_intelligence": engine_outputs[2],
            "behavior": engine_outputs[3]
        }

        # Evidence Fusion & Risk Aggregation
        assessment, combined_evidence = RiskAggregator.aggregate(engines_dict)

        # Deterministic Explainability
        explainability = ExplainabilityGenerator.generate(assessment, combined_evidence)

        total_duration_ms = int((time.perf_counter() - overall_start) * 1000)

        logger.info(
            f"Completed analysis id={analysis_id} risk={assessment.risk_score} "
            f"severity={assessment.severity} duration={total_duration_ms}ms"
        )

        return AnalysisResponse(
            analysis_id=analysis_id,
            input_type=normalized_data.input_type,
            indicator_hmac=normalized_data.indicator_hmac,
            created_at=datetime.now(timezone.utc).isoformat(),
            assessment=assessment,
            engines=engines_dict,
            explainability=explainability,
            language_info=normalized_data.metadata.get("language_info"),
            duration_ms=total_duration_ms
        )

