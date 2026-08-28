import os
import json
from typing import List, Dict
from app.detection.rules.rule_schema import DetectionRule


class RuleLoader:
    _rules_cache: Dict[str, List[DetectionRule]] = {}

    @classmethod
    def get_rules_dir(cls) -> str:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        return os.path.join(base_dir, "rules")

    @classmethod
    def load_rules_for_type(cls, input_type: str) -> List[DetectionRule]:
        if input_type in cls._rules_cache:
            return cls._rules_cache[input_type]

        filename = f"{input_type}_rules.json"
        if input_type in ["message", "social"]:
            filename = "message_rules.json"
        elif input_type in ["url", "qr"]:
            filename = "url_rules.json"
        elif input_type == "webpage":
            filename = "webpage_rules.json"
        elif input_type == "email":
            filename = "email_rules.json"

        file_path = os.path.join(cls.get_rules_dir(), filename)
        rules: List[DetectionRule] = []

        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                    for item in raw_data:
                        rules.append(DetectionRule(**item))
            except Exception as e:
                pass

        cls._rules_cache[input_type] = rules
        return rules

