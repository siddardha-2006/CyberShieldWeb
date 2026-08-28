"""
CyberShield Threat Intel Cache
------------------------------
In-memory cache for threat reputation lookups.
"""

from typing import Dict, Any, Optional


class ThreatIntelCache:
    _cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def get(cls, key: str) -> Optional[Dict[str, Any]]:
        # Only cache positive threat hits to prevent stale clean results
        return cls._cache.get(key)

    @classmethod
    def set(cls, key: str, data: Dict[str, Any]) -> None:
        # Only store malicious results in cache
        if data.get("score", 0) > 0:
            cls._cache[key] = data

    @classmethod
    def clear(cls):
        cls._cache.clear()
