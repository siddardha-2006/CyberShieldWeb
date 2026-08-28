import re
import urllib.parse
from typing import Dict, Any, Optional
import httpx


LANGUAGE_NAMES = {
    "hi": "Hindi",
    "te": "Telugu",
    "ta": "Tamil",
    "kn": "Kannada",
    "ml": "Malayalam",
    "bn": "Bengali",
    "mr": "Marathi",
    "pa": "Punjabi",
    "gu": "Gujarati",
    "ur": "Urdu",
    "es": "Spanish",
    "fr": "French",
    "de": "German",
    "ru": "Russian",
    "zh": "Chinese",
    "ja": "Japanese",
    "ar": "Arabic",
    "pt": "Portuguese",
    "id": "Indonesian",
    "it": "Italian",
    "tr": "Turkish",
    "vi": "Vietnamese",
    "en": "English",
}


class MultiLanguageTranslator:
    """
    Asynchronous and synchronous resilient translation helper for regional
    and international languages with zero API key requirement.
    """

    _cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def is_likely_non_english(cls, text: str) -> bool:
        """
        Quick deterministic check if text contains non-Latin scripts
        (Devanagari, Telugu, Tamil, Cyrillic, Arabic, Chinese, etc.)
        or prominent regional greeting phrases.
        """
        if not text or not text.strip():
            return False
        
        # Check non-ASCII characters ratio or non-latin unicode blocks
        non_ascii_count = sum(1 for c in text if ord(c) > 127)
        if non_ascii_count >= 3:
            return True
            
        # Common romanized regional keywords (Hinglish/Tanglish/etc.)
        lower = text.lower()
        regional_keywords = [
            "badhai", "namaste", "namaskaram", "vanakkam", "shulka", "paisa", "rupaye",
            "karein", "kijiye", "cheyyandi", "karo", "dijiye", "bhejo", "chuna gaya"
        ]
        if any(w in lower for w in regional_keywords):
            return True

        return False

    @classmethod
    async def translate_text(cls, text: str) -> Dict[str, Any]:
        """
        Translates regional/foreign language text to English asynchronously.
        """
        clean_text = text.strip()
        if not clean_text:
            return {
                "is_translated": False,
                "detected_language": "English",
                "original_text": clean_text,
                "translated_text": clean_text
            }

        # Check in-memory cache
        if clean_text in cls._cache:
            return cls._cache[clean_text]

        # If already pure standard English with no non-ascii, return immediately
        if not cls.is_likely_non_english(clean_text):
            res = {
                "is_translated": False,
                "detected_language": "English",
                "original_text": clean_text,
                "translated_text": clean_text
            }
            cls._cache[clean_text] = res
            return res

        # Attempt neural translation via MyMemory API
        try:
            async with httpx.AsyncClient(timeout=3.5) as client:
                params = {
                    "q": clean_text,
                    "langpair": "autodetect|en"
                }
                resp = await client.get("https://api.mymemory.translated.net/get", params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    response_data = data.get("responseData", {})
                    translated = response_data.get("translatedText", "")
                    raw_lang = response_data.get("detectedLanguage", "unknown").lower()
                    
                    lang_name = LANGUAGE_NAMES.get(raw_lang, raw_lang.upper())
                    
                    if translated and translated.lower() != clean_text.lower():
                        res = {
                            "is_translated": True,
                            "detected_language": lang_name,
                            "original_text": clean_text,
                            "translated_text": translated
                        }
                        cls._cache[clean_text] = res
                        return res
        except Exception as e:
            # Non-blocking graceful degradation
            pass

        # Fallback: if translation unavailable or failed
        res = {
            "is_translated": False,
            "detected_language": "Regional / Auto",
            "original_text": clean_text,
            "translated_text": clean_text
        }
        cls._cache[clean_text] = res
        return res

    @classmethod
    def translate_text_sync(cls, text: str) -> Dict[str, Any]:
        """
        Synchronous wrapper for normalization pipeline.
        """
        clean_text = text.strip()
        if not clean_text or not cls.is_likely_non_english(clean_text):
            return {
                "is_translated": False,
                "detected_language": "English",
                "original_text": clean_text,
                "translated_text": clean_text
            }

        if clean_text in cls._cache:
            return cls._cache[clean_text]

        try:
            with httpx.Client(timeout=3.5) as client:
                params = {
                    "q": clean_text,
                    "langpair": "autodetect|en"
                }
                resp = client.get("https://api.mymemory.translated.net/get", params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    response_data = data.get("responseData", {})
                    translated = response_data.get("translatedText", "")
                    raw_lang = response_data.get("detectedLanguage", "unknown").lower()
                    lang_name = LANGUAGE_NAMES.get(raw_lang, raw_lang.upper())

                    if translated and translated.lower() != clean_text.lower():
                        res = {
                            "is_translated": True,
                            "detected_language": lang_name,
                            "original_text": clean_text,
                            "translated_text": translated
                        }
                        cls._cache[clean_text] = res
                        return res
        except Exception:
            pass

        res = {
            "is_translated": False,
            "detected_language": "Regional / Auto",
            "original_text": clean_text,
            "translated_text": clean_text
        }
        cls._cache[clean_text] = res
        return res

