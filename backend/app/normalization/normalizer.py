import uuid
from typing import Dict, Any, List
from app.schemas.analysis import NormalizedInput
from app.extraction.url import UrlExtractor
from app.extraction.message import MessageExtractor
from app.extraction.email import EmailExtractor
from app.extraction.qr import QrExtractor
from app.extraction.webpage import WebpageExtractor
from app.normalization.translator import MultiLanguageTranslator
from app.core.security import generate_hmac_identifier


class ContentNormalizer:
    """
    Central router that converts any heterogeneous raw input
    into a strictly validated, strongly typed NormalizedInput payload.
    Automatically detects regional languages and translates for deep security analysis.
    """

    @classmethod
    def normalize_url(cls, url: str) -> NormalizedInput:
        extracted = UrlExtractor.extract(url)
        analysis_id = str(uuid.uuid4())
        indicator_hmac = generate_hmac_identifier(extracted["normalized_url"])
        
        return NormalizedInput(
            analysis_id=analysis_id,
            input_type="url",
            text=extracted["normalized_url"],
            urls=[extracted["normalized_url"]],
            domains=[extracted["registered_domain"]] if extracted["registered_domain"] else [],
            emails=[],
            phones=[],
            headers={},
            metadata={"url_details": extracted},
            indicator_hmac=indicator_hmac
        )

    @classmethod
    def normalize_message(cls, text: str, sender: str = None) -> NormalizedInput:
        extracted = MessageExtractor.extract(text, sender)
        analysis_id = str(uuid.uuid4())
        indicator_hmac = generate_hmac_identifier(text[:120])
        
        # Check and translate regional languages if needed
        lang_res = MultiLanguageTranslator.translate_text_sync(text)
        effective_text = lang_res["translated_text"] if lang_res["is_translated"] else extracted["raw_text"]

        return NormalizedInput(
            analysis_id=analysis_id,
            input_type="message",
            text=effective_text,
            urls=extracted["urls"],
            domains=extracted["domains"],
            emails=extracted["emails"],
            phones=extracted["phones"],
            headers={},
            metadata={
                "message_details": extracted,
                "language_info": lang_res
            },
            indicator_hmac=indicator_hmac
        )

    @classmethod
    def normalize_raw_email(cls, raw_email: str) -> NormalizedInput:
        extracted = EmailExtractor.extract_from_raw_text(raw_email)
        analysis_id = str(uuid.uuid4())
        indicator_hmac = generate_hmac_identifier(f"{extracted.get('sender', '')}:{extracted.get('subject', '')}:{raw_email[:60]}")
        
        raw_combined = f"{extracted.get('subject', '')}\n{extracted.get('body_snippet', '')}"
        lang_res = MultiLanguageTranslator.translate_text_sync(raw_email)
        effective_text = lang_res["translated_text"] if lang_res["is_translated"] else raw_email

        return NormalizedInput(
            analysis_id=analysis_id,
            input_type="email",
            text=effective_text,
            urls=extracted["urls"],
            domains=extracted["domains"],
            emails=[extracted["sender"]] + ([extracted["reply_to"]] if extracted.get("reply_to") else []),
            phones=[],
            headers=extracted.get("headers", {}),
            metadata={
                "email_details": extracted,
                "language_info": lang_res,
                "is_raw_pasted": True
            },
            indicator_hmac=indicator_hmac
        )

    @classmethod
    def normalize_email(cls, sender: str, subject: str, body: str, reply_to: str = None, headers: Dict[str, str] = None) -> NormalizedInput:
        extracted = EmailExtractor.extract(sender, subject, body, reply_to, headers)
        analysis_id = str(uuid.uuid4())
        indicator_hmac = generate_hmac_identifier(f"{sender}:{subject}")
        
        raw_combined = f"{subject}\n{body}"
        lang_res = MultiLanguageTranslator.translate_text_sync(raw_combined)
        effective_text = lang_res["translated_text"] if lang_res["is_translated"] else raw_combined

        return NormalizedInput(
            analysis_id=analysis_id,
            input_type="email",
            text=effective_text,
            urls=extracted["urls"],
            domains=extracted["domains"],
            emails=[sender] + ([reply_to] if reply_to else []),
            phones=[],
            headers=headers or {},
            metadata={
                "email_details": extracted,
                "language_info": lang_res
            },
            indicator_hmac=indicator_hmac
        )

    @classmethod
    def normalize_qr(cls, image_base64: str = None, decoded_payload: str = None) -> NormalizedInput:
        extracted = QrExtractor.extract(image_base64, decoded_payload)
        payload = extracted["decoded_payload"]
        analysis_id = str(uuid.uuid4())
        indicator_hmac = generate_hmac_identifier(payload or "empty_qr")
        
        urls = [payload] if extracted["is_url"] else []
        return NormalizedInput(
            analysis_id=analysis_id,
            input_type="qr",
            text=payload,
            urls=urls,
            domains=[],
            emails=[],
            phones=[],
            headers={},
            metadata={"qr_details": extracted},
            indicator_hmac=indicator_hmac
        )

    @classmethod
    def normalize_webpage(cls, url: str, html_content: str = None) -> NormalizedInput:
        url_extracted = UrlExtractor.extract(url)
        web_extracted = WebpageExtractor.extract_static(html_content or "", url) if html_content else {}
        
        analysis_id = str(uuid.uuid4())
        indicator_hmac = generate_hmac_identifier(url_extracted["normalized_url"])
        
        return NormalizedInput(
            analysis_id=analysis_id,
            input_type="webpage",
            text=web_extracted.get("text_sample", url),
            urls=[url_extracted["normalized_url"]],
            domains=[url_extracted["registered_domain"]] if url_extracted["registered_domain"] else [],
            emails=[],
            phones=[],
            headers={},
            metadata={
                "url_details": url_extracted,
                "webpage_details": web_extracted
            },
            indicator_hmac=indicator_hmac
        )

    @classmethod
    def normalize_social(cls, text: str, platform: str = "generic") -> NormalizedInput:
        extracted = MessageExtractor.extract(text)
        analysis_id = str(uuid.uuid4())
        indicator_hmac = generate_hmac_identifier(text[:120])
        
        # Check and translate regional languages if needed
        lang_res = MultiLanguageTranslator.translate_text_sync(text)
        effective_text = lang_res["translated_text"] if lang_res["is_translated"] else extracted["raw_text"]

        return NormalizedInput(
            analysis_id=analysis_id,
            input_type="social",
            text=effective_text,
            urls=extracted["urls"],
            domains=extracted["domains"],
            emails=extracted["emails"],
            phones=extracted["phones"],
            headers={},
            metadata={
                "social_details": extracted, 
                "platform": platform,
                "language_info": lang_res
            },
            indicator_hmac=indicator_hmac
        )
