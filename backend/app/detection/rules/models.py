"""
CyberShield Rule Engine Models
------------------------------
Defines the schema for signals, detection rules, triggered evidence,
and correlation results per CyberShield Rule Engine Specification.
"""

from typing import Dict, Any, List, Optional, Literal
from pydantic import BaseModel, Field


class Signal(BaseModel):
    category: str
    name: str
    value: Any
    confidence: float = 1.0
    source_engine: str = "rules"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DetectionRule(BaseModel):
    id: str
    title: str
    category: str  # URL_STRUCTURE, URL_DOMAIN, BRAND_IMPERSONATION, etc.
    description: str
    weight: int = 10
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    confidence_requirement: float = 0.50
    evidence_group_id: Optional[str] = None  # To prevent double-counting
    is_deterministic: bool = True  # If True, weight is not multiplied by confidence


class TriggeredRule(BaseModel):
    rule_id: str
    title: str
    description: str
    points: int
    severity: Literal["low", "medium", "high", "critical"]
    category: str
    evidence_group_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RuleEvaluationResult(BaseModel):
    risk_score: int
    classification: Literal["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float
    triggered_rules: List[TriggeredRule]
    indicators: List[str]
    explanation: str
    recommendation: str
    engine: str = "rule_engine"
    rule_version: str = "1.0.0"

