from pydantic import BaseModel
from typing import Optional, Any, Literal


class DetectionRule(BaseModel):
    id: str
    title: str
    description: str
    weight: int = 10
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    category: str = "general"
    pattern_type: Literal["regex", "property", "keyword", "custom"]
    field: str
    operator: Optional[str] = "equals" # equals, gte, lte, contains, regex
    value: Optional[Any] = None
    pattern: Optional[str] = None

