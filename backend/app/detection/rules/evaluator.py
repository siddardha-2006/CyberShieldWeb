"""
CyberShield Rule Evaluator
--------------------------
Evaluates normalized engine indicators against the Rule Registry,
applying multi-signal correlation, duplicate suppression, and allowlist protection.
"""

import re
from typing import Dict, Any, List, Tuple
from app.schemas.analysis import NormalizedInput
from app.detection.rules.models import TriggeredRule, DetectionRule
from app.detection.rules.registry import (
    RULES_CATALOG,
    TRUSTED_ALLOWLIST_DOMAINS,
    CONFIGURED_SUSPICIOUS_TLDS
)


class RuleEvaluator:
    @classmethod
    def extract_context(cls, data: NormalizedInput) -> Dict[str, Any]:
        """Extract a consolidated context dictionary of all normalized indicators."""
        ctx: Dict[str, Any] = {
            "input_type": data.input_type,
            "text": data.text or "",
            "urls": data.urls or []
        }

        lower_text = (data.text or "").lower()

        if data.input_type in ["url", "qr"] and "url_details" in data.metadata:
            ctx.update(data.metadata["url_details"])
        elif data.input_type in ["message", "social"] and "message_details" in data.metadata:
            msg_details = data.metadata["message_details"]
            indicators = msg_details.get("indicators", {})
            ctx.update(indicators)
            ctx.update(msg_details)
        elif data.input_type == "email" and "email_details" in data.metadata:
            email_details = data.metadata["email_details"]
            auth_signals = email_details.get("auth_signals", {})
            ctx.update(auth_signals)
            ctx.update(email_details)
        elif data.input_type == "webpage" and "webpage_details" in data.metadata:
            ctx.update(data.metadata["webpage_details"])
            if "url_details" in data.metadata:
                ctx.update(data.metadata["url_details"])

        # Linguistic and semantic signal flags
        ctx["has_urgency"] = bool(ctx.get("urgency_count", 0) > 0) or any(
            w in lower_text for w in ["urgent", "immediately", "within 24 hours", "asap", "final warning", "last chance", "action required"]
        )
        ctx["has_threat"] = any(
            w in lower_text for w in ["suspended", "blocked", "restricted", "deactivated", "frozen", "legal action", "compromised", "account will be closed"]
        )
        ctx["has_reward"] = any(
            w in lower_text for w in [
                "you have won", "claim prize", "lottery winner", "free gift", "reward notification", 
                "airdrop", "shortlisted", "remote job", "earn per day", "work from home", 
                "daily income", "part-time job", "profile has been shortlisted", "earn from home"
            ]
        )
        ctx["has_credential_request"] = bool(ctx.get("credential_count", 0) > 0) or any(
            w in lower_text for w in [
                "password", "otp", "pin", "cvv", "verification code", "security code", 
                "seed phrase", "private key", "mnemonic", "credentials", "sign in using", "organization credentials"
            ]
        )
        ctx["has_otp"] = bool(ctx.get("has_otp_request", False)) or any(
            w in lower_text for w in ["otp", "one-time password", "verification code", "2fa code", "security code"]
        )
        ctx["has_financial_request"] = bool(ctx.get("financial_count", 0) > 0) or any(
            w in lower_text for w in [
                "wire transfer", "bank transfer", "crypto", "bitcoin", "processing fee", 
                "direct deposit", "invoice", "refund", "gift card", "registration fee", 
                "entry fee", "security deposit", "one-time registration", "advance fee", "upfront fee"
            ]
        ) or bool(re.search(r'[₹$€£]\s*\d+|\b\d+\s*(?:usd|inr|eur|rs|rupees)\b', lower_text))

        # Email spoofing flags
        ctx["from_replyto_mismatch"] = bool(ctx.get("is_mismatched_reply_to", False)) or bool(ctx.get("has_spoof_mismatch", False))
        ctx["executive_impersonation"] = any(
            w in lower_text for w in ["ceo", "chief executive", "president", "director", "cfo", "confidential wire", "urgent wire"]
        ) or ("ceo@" in str(ctx.get("sender", "")).lower())

        return ctx

    @classmethod
    def evaluate(cls, data: NormalizedInput) -> Tuple[List[TriggeredRule], bool]:
        """
        Evaluate all applicable security rules and correlation combinations.
        Returns:
            Tuple of (triggered_rules, is_critical_escalated)
        """
        ctx = cls.extract_context(data)
        triggered_by_group: Dict[str, TriggeredRule] = {}
        standalone_triggered: List[TriggeredRule] = []

        registered_domain = str(ctx.get("registered_domain", "")).lower()
        hostname = str(ctx.get("hostname", "")).lower()
        suffix = str(ctx.get("suffix", "")).lower()
        is_brand_imp = bool(ctx.get("is_brand_impersonation", False))
        is_allowlisted = bool(registered_domain in TRUSTED_ALLOWLIST_DOMAINS and not is_brand_imp and data.input_type == "url")

        def trigger(rule_id: str, dynamic_points: int = None, metadata: Dict[str, Any] = None):
            rule: DetectionRule = RULES_CATALOG.get(rule_id)
            if not rule:
                return

            points = dynamic_points if dynamic_points is not None else rule.weight
            item = TriggeredRule(
                rule_id=rule.id,
                title=rule.title,
                description=rule.description,
                points=points,
                severity=rule.severity,
                category=rule.category,
                evidence_group_id=rule.evidence_group_id,
                metadata=metadata or {}
            )

            group = rule.evidence_group_id
            if group:
                if group not in triggered_by_group or points > triggered_by_group[group].points:
                    triggered_by_group[group] = item
            else:
                standalone_triggered.append(item)

        # -------------------------------------------------------------
        # 1. URL Structural Rules (§7)
        # -------------------------------------------------------------
        if ctx.get("is_ip_address"):
            trigger("URL_STRUCTURE_001")

        if suffix in CONFIGURED_SUSPICIOUS_TLDS or ctx.get("is_suspicious_tld"):
            trigger("URL_DOMAIN_001")

        if int(ctx.get("subdomain_depth", 0)) >= 3:
            trigger("URL_DOMAIN_002")

        if len(hostname) >= 60:
            trigger("URL_DOMAIN_003")

        if int(ctx.get("url_length", 0)) >= 200:
            trigger("URL_STRUCTURE_002")

        if int(ctx.get("hyphen_count", 0)) >= 3:
            trigger("URL_DOMAIN_004")

        if bool(ctx.get("has_excessive_digits")):
            trigger("URL_DOMAIN_005")

        if float(ctx.get("entropy", 0.0)) >= 3.8 and not is_allowlisted:
            trigger("URL_DOMAIN_006")

        if bool(ctx.get("has_punycode")):
            trigger("URL_DOMAIN_007")

        if bool(ctx.get("has_hex_encoding")):
            trigger("URL_OBFUSCATION_001")

        if bool(ctx.get("has_open_redirect_param")):
            trigger("URL_REDIRECT_001")

        # -------------------------------------------------------------
        # 2. Brand Impersonation Rules (§8)
        # -------------------------------------------------------------
        if is_brand_imp:
            trigger("BRAND_001", metadata={"brand": ctx.get("impersonated_brand")})

        # -------------------------------------------------------------
        # 3. Path & Sensitive Parameter Rules (§9, §10)
        # -------------------------------------------------------------
        has_creds = bool(ctx.get("has_credential_keywords_in_path")) or bool(ctx.get("has_crypto_seed_solicitation"))
        if has_creds:
            trigger("URL_PATH_001")

        if bool(ctx.get("has_crypto_seed_solicitation")) or bool(ctx.get("has_embedded_email")):
            trigger("URL_PARAM_001")

        # -------------------------------------------------------------
        # 4. Transport Rules (§11)
        # -------------------------------------------------------------
        if bool(ctx.get("is_http")) and has_creds:
            trigger("TRANSPORT_001")

        # -------------------------------------------------------------
        # 5. Message / Text Rules (§14)
        # -------------------------------------------------------------
        if bool(ctx.get("has_urgency")):
            trigger("TEXT_URGENCY_001")

        if bool(ctx.get("has_threat")):
            trigger("TEXT_FEAR_001")

        if bool(ctx.get("has_reward")):
            trigger("TEXT_REWARD_001")

        if bool(ctx.get("has_credential_request")) or bool(ctx.get("has_otp")):
            trigger("TEXT_CREDENTIAL_001")

        if bool(ctx.get("has_financial_request")):
            trigger("TEXT_FINANCIAL_001")

        # -------------------------------------------------------------
        # 6. Email Rules (§15)
        # -------------------------------------------------------------
        if bool(ctx.get("from_replyto_mismatch")):
            trigger("EMAIL_001")

        if bool(ctx.get("display_name_spoofed")):
            trigger("EMAIL_002")

        if bool(ctx.get("executive_impersonation")) and bool(ctx.get("has_financial_request")):
            trigger("EMAIL_003")

        # -------------------------------------------------------------
        # 7. Webpage Rules (§16)
        # -------------------------------------------------------------
        if bool(ctx.get("has_login_form")):
            trigger("WEB_001")

        if bool(ctx.get("has_password_field")):
            trigger("WEB_002")

        if bool(ctx.get("has_otp_field")):
            trigger("WEB_003")

        if bool(ctx.get("has_payment_field")):
            trigger("WEB_004")

        if bool(ctx.get("cross_domain_submission")):
            trigger("WEB_005")

        # -------------------------------------------------------------
        # 8. QR Rules (§17)
        # -------------------------------------------------------------
        if data.input_type == "qr":
            if bool(ctx.get("is_shortener_domain")):
                trigger("QR_002")
            if has_creds:
                trigger("QR_003")

        # -------------------------------------------------------------
        # 9. Correlation & Combination Rules (§8.4, §8.5, §18)
        # -------------------------------------------------------------
        is_suspicious_domain = is_brand_imp or suffix in CONFIGURED_SUSPICIOUS_TLDS or bool(ctx.get("is_ip_address"))

        # Brand + Login
        if is_brand_imp and (has_creds or bool(ctx.get("has_login_form"))):
            trigger("BRAND_COMBO_001")

        # Brand + Credential Harvesting
        if is_brand_imp and (bool(ctx.get("has_crypto_seed_solicitation")) or bool(ctx.get("has_password_field")) or has_creds):
            trigger("BRAND_COMBO_002")

        # COMBO_001: Urgency + Credential Request
        if bool(ctx.get("has_urgency")) and (bool(ctx.get("has_credential_request")) or bool(ctx.get("has_otp"))):
            trigger("COMBO_001")

        # COMBO_002: Fear/Threat + Login
        if bool(ctx.get("has_threat")) and (has_creds or bool(ctx.get("has_login_form")) or "login" in (data.text or "").lower()):
            trigger("COMBO_002")

        # COMBO_003: Reward + Financial
        if bool(ctx.get("has_reward")) and bool(ctx.get("has_financial_request")):
            trigger("COMBO_003")

        # COMBO_004: Impersonation + Financial
        if (is_brand_imp or bool(ctx.get("executive_impersonation"))) and bool(ctx.get("has_financial_request")):
            trigger("COMBO_004")

        # COMBO_005: OTP + External URL
        if (bool(ctx.get("has_otp")) or bool(ctx.get("has_otp_field"))) and bool(data.urls):
            trigger("COMBO_005")

        # COMBO_006: Password + Suspicious Domain
        if (bool(ctx.get("has_password_field")) or has_creds) and is_suspicious_domain:
            trigger("COMBO_006")

        # -------------------------------------------------------------
        # 10. High-Confidence Critical Escalation Rules (§19)
        # -------------------------------------------------------------
        is_critical_escalated = False

        # CRITICAL_001: Brand impersonation + credential harvesting
        if is_brand_imp and has_creds:
            is_critical_escalated = True

        # CRITICAL_002: OTP request + suspicious external URL + urgency
        if bool(ctx.get("has_otp")) and (is_suspicious_domain or bool(data.urls)) and bool(ctx.get("has_urgency")):
            is_critical_escalated = True

        # CRITICAL_003: Executive impersonation + Reply-To mismatch + wire request
        if bool(ctx.get("executive_impersonation")) and bool(ctx.get("from_replyto_mismatch")) and bool(ctx.get("has_financial_request")):
            is_critical_escalated = True

        # CRITICAL_004: Crypto seed phrase harvesting
        if bool(ctx.get("has_crypto_seed_solicitation")):
            is_critical_escalated = True

        # -------------------------------------------------------------
        # 11. False Positive Allowlist Protection (§20)
        # -------------------------------------------------------------
        all_triggered = list(triggered_by_group.values()) + standalone_triggered

        if is_allowlisted:
            weak_categories = {"URL_STRUCTURE", "URL_DOMAIN", "URL_PATH", "URL_OBFUSCATION", "URL_REDIRECT"}
            filtered_triggered = [r for r in all_triggered if r.category not in weak_categories]
            all_triggered = filtered_triggered
            is_critical_escalated = False

        return all_triggered, is_critical_escalated
