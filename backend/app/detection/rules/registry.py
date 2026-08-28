"""
CyberShield Rule Registry
-------------------------
Catalog of all deterministic security rules, multi-signal correlation rules,
and critical escalation policies conforming to CyberShield Specification.
"""

from typing import Dict, List
from app.detection.rules.models import DetectionRule

# Configurable Allowlist of verified top-tier domains
TRUSTED_ALLOWLIST_DOMAINS = {
    "google.com", "google.co.in", "google.co.uk", "google.com.br", "gmail.com", "youtube.com",
    "wikipedia.org", "wikimedia.org",
    "github.com", "github.io", "gitlab.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "azure.com",
    "apple.com", "icloud.com", "itunes.com",
    "amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com",
    "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com", "linkedin.com",
    "reddit.com", "netflix.com", "spotify.com", "stackoverflow.com", "cnn.com", "bbc.com",
    "myspace.com", "vimeo.com", "dailymotion.com"
}

# Configurable high-risk / disposable TLDs
CONFIGURED_SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "work", "zip", "tk", "icu", "buzz", "fit",
    "monster", "live", "rest", "cf", "gq", "ga", "ml", "quest", "fun",
    "space", "site", "website", "racing", "download", "stream", "bid", "loan", "win"
}

# Master Rule Definitions
RULES_CATALOG: Dict[str, DetectionRule] = {
    # -------------------------------------------------------------
    # 7. URL Structure & Domain Rules
    # -------------------------------------------------------------
    "URL_STRUCTURE_001": DetectionRule(
        id="URL_STRUCTURE_001",
        title="Raw IP Address Host",
        category="URL_STRUCTURE",
        description="Hostname is an IPv4 or IPv6 numerical address rather than a registered domain.",
        weight=25,
        severity="medium",
        evidence_group_id="ip_host"
    ),
    "URL_DOMAIN_001": DetectionRule(
        id="URL_DOMAIN_001",
        title="Suspicious Top-Level Domain (TLD)",
        category="URL_DOMAIN",
        description="Hostname uses a top-level domain frequently associated with abuse and disposable campaigns.",
        weight=10,
        severity="low",
        evidence_group_id="suspicious_tld"
    ),
    "URL_DOMAIN_002": DetectionRule(
        id="URL_DOMAIN_002",
        title="Excessive Subdomain Levels",
        category="URL_DOMAIN",
        description="Hostname contains more than 3 nested subdomain levels used to obscure the destination.",
        weight=10,
        severity="low",
        evidence_group_id="subdomain_depth"
    ),
    "URL_DOMAIN_003": DetectionRule(
        id="URL_DOMAIN_003",
        title="Excessive Domain Length",
        category="URL_DOMAIN",
        description="Hostname length exceeds configured threshold (60+ characters).",
        weight=10,
        severity="low",
        evidence_group_id="domain_length"
    ),
    "URL_STRUCTURE_002": DetectionRule(
        id="URL_STRUCTURE_002",
        title="Excessive URL Length",
        category="URL_STRUCTURE",
        description="Complete URL length exceeds 200 characters.",
        weight=10,
        severity="low",
        evidence_group_id="url_length"
    ),
    "URL_DOMAIN_004": DetectionRule(
        id="URL_DOMAIN_004",
        title="Excessive Hyphens in Domain",
        category="URL_DOMAIN",
        description="Hostname contains 3 or more suspiciously positioned hyphens.",
        weight=8,
        severity="low",
        evidence_group_id="hyphen_count"
    ),
    "URL_DOMAIN_005": DetectionRule(
        id="URL_DOMAIN_005",
        title="Excessive Numeric Characters in Hostname",
        category="URL_DOMAIN",
        description="Hostname has an unusually high numeric-to-alphabetic ratio.",
        weight=8,
        severity="low",
        evidence_group_id="digit_density"
    ),
    "URL_DOMAIN_006": DetectionRule(
        id="URL_DOMAIN_006",
        title="High Entropy / Random-Looking Domain",
        category="URL_DOMAIN",
        description="Domain character entropy exceeds threshold indicating automated DGA generation.",
        weight=15,
        severity="medium",
        evidence_group_id="domain_entropy"
    ),
    "URL_DOMAIN_007": DetectionRule(
        id="URL_DOMAIN_007",
        title="Punycode Homoglyph Identifier",
        category="URL_DOMAIN",
        description="Hostname contains internationalized punycode prefix ('xn--').",
        weight=15,
        severity="medium",
        evidence_group_id="punycode"
    ),
    "URL_DOMAIN_008": DetectionRule(
        id="URL_DOMAIN_008",
        title="Unicode Homograph Brand Spoof",
        category="URL_DOMAIN",
        description="Visually deceptive Unicode characters resemble a trusted brand or domain.",
        weight=25,
        severity="high",
        evidence_group_id="homograph"
    ),
    "URL_OBFUSCATION_001": DetectionRule(
        id="URL_OBFUSCATION_001",
        title="Excessive Percent Encoding",
        category="URL_OBFUSCATION",
        description="URL contains excessive percent-encoding across path or query components.",
        weight=10,
        severity="low",
        evidence_group_id="encoding"
    ),
    "URL_OBFUSCATION_002": DetectionRule(
        id="URL_OBFUSCATION_002",
        title="Double URL Encoding Detected",
        category="URL_OBFUSCATION",
        description="URL contains double-encoded characters designed to bypass inspection gateways.",
        weight=15,
        severity="medium",
        evidence_group_id="double_encoding"
    ),
    "URL_REDIRECT_001": DetectionRule(
        id="URL_REDIRECT_001",
        title="External Redirect Parameter Detected",
        category="URL_REDIRECT",
        description="URL contains an open-redirect parameter (url=, redirect=, target=, next=).",
        weight=10,
        severity="low",
        evidence_group_id="open_redirect"
    ),

    # -------------------------------------------------------------
    # 8. Brand Impersonation Rules
    # -------------------------------------------------------------
    "BRAND_001": DetectionRule(
        id="BRAND_001",
        title="Brand in Non-Official Domain",
        category="BRAND_IMPERSONATION",
        description="Recognized high-value brand name appears in hostname/domain on an unauthorized third-party registrar.",
        weight=30,
        severity="high",
        evidence_group_id="brand_domain_mismatch"
    ),
    "BRAND_002": DetectionRule(
        id="BRAND_002",
        title="Brand Typosquatting / Edit-Distance Match",
        category="BRAND_IMPERSONATION",
        description="Hostname is a close edit-distance typosquat match to a protected brand.",
        weight=25,
        severity="high",
        evidence_group_id="typosquatting"
    ),
    "BRAND_003": DetectionRule(
        id="BRAND_003",
        title="Visual Character Substitution in Brand",
        category="BRAND_IMPERSONATION",
        description="Brand impersonation uses visually similar character substitutions (e.g. 0->o, 1->l).",
        weight=25,
        severity="high",
        evidence_group_id="char_substitution"
    ),
    "BRAND_COMBO_001": DetectionRule(
        id="BRAND_COMBO_001",
        title="Brand Impersonation + Authentication Lure",
        category="CORRELATION",
        description="Brand impersonation combined with login/sign-in behavior or path.",
        weight=20,
        severity="high",
        evidence_group_id="brand_login_combo"
    ),
    "BRAND_COMBO_002": DetectionRule(
        id="BRAND_COMBO_002",
        title="Brand Impersonation + Credential/Seed Solicitation",
        category="CORRELATION",
        description="Brand impersonation combined with password, OTP, or crypto seed harvesting.",
        weight=30,
        severity="critical",
        evidence_group_id="brand_credential_combo"
    ),

    # -------------------------------------------------------------
    # 9. URL Path & Parameter Rules
    # -------------------------------------------------------------
    "URL_PATH_001": DetectionRule(
        id="URL_PATH_001",
        title="Sensitive Authentication Path",
        category="URL_PATH",
        description="Sensitive authentication or account recovery path detected (/login, /signin, /verify, /account, /password, /restore).",
        weight=15,
        severity="medium",
        evidence_group_id="sensitive_path"
    ),
    "URL_PARAM_001": DetectionRule(
        id="URL_PARAM_001",
        title="Sensitive Credential/Seed Parameter",
        category="URL_PARAMETER",
        description="Query parameter solicits sensitive credentials (password, otp, pin, seed, privatekey, cvv, token).",
        weight=15,
        severity="medium",
        evidence_group_id="sensitive_param"
    ),

    # -------------------------------------------------------------
    # 11. Transport Rules
    # -------------------------------------------------------------
    "TRANSPORT_001": DetectionRule(
        id="TRANSPORT_001",
        title="Insecure HTTP Transport with Credential Form",
        category="URL_STRUCTURE",
        description="Unencrypted HTTP protocol used where sensitive credential or login data is processed.",
        weight=20,
        severity="medium",
        evidence_group_id="http_credentials"
    ),

    # -------------------------------------------------------------
    # 12. Redirect Rules
    # -------------------------------------------------------------
    "REDIRECT_001": DetectionRule(
        id="REDIRECT_001",
        title="Multi-Hop Redirection Chain",
        category="URL_REDIRECT",
        description="Redirect count exceeds 2 hops in resolution chain.",
        weight=10,
        severity="low",
        evidence_group_id="redirect_chain"
    ),
    "REDIRECT_002": DetectionRule(
        id="REDIRECT_002",
        title="Cross-Domain Redirection",
        category="URL_REDIRECT",
        description="Redirect chain crosses into a different registered root domain.",
        weight=10,
        severity="medium",
        evidence_group_id="cross_domain_redirect"
    ),
    "REDIRECT_003": DetectionRule(
        id="REDIRECT_003",
        title="Suspicious Final Redirect Destination",
        category="URL_REDIRECT",
        description="Final destination domain of redirect chain is unverified or suspicious.",
        weight=30,
        severity="high",
        evidence_group_id="final_dest_suspicious"
    ),
    "REDIRECT_004": DetectionRule(
        id="REDIRECT_004",
        title="Complex Multi-Redirect to Suspicious Endpoint",
        category="CORRELATION",
        description="Multiple redirect hops leading into a suspicious destination endpoint.",
        weight=15,
        severity="high",
        evidence_group_id="complex_redirect_combo"
    ),

    # -------------------------------------------------------------
    # 13. Reputation Rules
    # -------------------------------------------------------------
    "REPUTATION_001": DetectionRule(
        id="REPUTATION_001",
        title="Known Malicious Domain (Threat Intelligence)",
        category="REPUTATION",
        description="Domain flagged as malicious in verified global threat intelligence feeds.",
        weight=60,
        severity="critical",
        evidence_group_id="reputation_malicious"
    ),
    "REPUTATION_002": DetectionRule(
        id="REPUTATION_002",
        title="Known Phishing Domain (PhishTank/URLhaus)",
        category="REPUTATION",
        description="Domain is verified as an active phishing host in threat databases.",
        weight=60,
        severity="critical",
        evidence_group_id="reputation_phish"
    ),
    "REPUTATION_003": DetectionRule(
        id="REPUTATION_003",
        title="Previously Reported Suspicious Domain",
        category="REPUTATION",
        description="Domain was previously flagged in threat hunting reports.",
        weight=40,
        severity="high",
        evidence_group_id="reputation_reported"
    ),
    "REPUTATION_004": DetectionRule(
        id="REPUTATION_004",
        title="Known Legitimate Domain (Verified Allowlist)",
        category="REPUTATION",
        description="Domain is an authoritative, verified global platform.",
        weight=-20,
        severity="low",
        evidence_group_id="reputation_legit"
    ),

    # -------------------------------------------------------------
    # 14. Message / Text Linguistic Rules
    # -------------------------------------------------------------
    "TEXT_URGENCY_001": DetectionRule(
        id="TEXT_URGENCY_001",
        title="Urgency / Deadline Manipulation",
        category="TEXT_SOCIAL_ENGINEERING",
        description="Message employs artificial urgency (immediately, within 24 hours, last chance) to force hasty action.",
        weight=10,
        severity="low",
        evidence_group_id="text_urgency"
    ),
    "TEXT_FEAR_001": DetectionRule(
        id="TEXT_FEAR_001",
        title="Fear / Account Threat Language",
        category="TEXT_SOCIAL_ENGINEERING",
        description="Message threatens account suspension, legal action, or security compromise.",
        weight=10,
        severity="low",
        evidence_group_id="text_fear"
    ),
    "TEXT_REWARD_001": DetectionRule(
        id="TEXT_REWARD_001",
        title="Unexpected Prize / Lottery Lure",
        category="TEXT_SOCIAL_ENGINEERING",
        description="Message promises unsolicited prizes, lottery winnings, or financial rewards.",
        weight=10,
        severity="low",
        evidence_group_id="text_reward"
    ),
    "TEXT_CREDENTIAL_001": DetectionRule(
        id="TEXT_CREDENTIAL_001",
        title="Credential / OTP / Seed Solicitation",
        category="TEXT_CREDENTIAL",
        description="Message solicits password, OTP, verification code, PIN, or crypto seed phrase.",
        weight=25,
        severity="high",
        evidence_group_id="text_credential"
    ),
    "TEXT_FINANCIAL_001": DetectionRule(
        id="TEXT_FINANCIAL_001",
        title="Financial / Wire Transfer Request",
        category="TEXT_FINANCIAL",
        description="Message requests wire transfer, crypto payment, gift card purchase, or urgent invoice processing.",
        weight=20,
        severity="medium",
        evidence_group_id="text_financial"
    ),

    # -------------------------------------------------------------
    # 15. Email Rules
    # -------------------------------------------------------------
    "EMAIL_001": DetectionRule(
        id="EMAIL_001",
        title="From vs Reply-To Domain Mismatch",
        category="EMAIL",
        description="Sender From address domain does not match the Reply-To destination domain.",
        weight=30,
        severity="high",
        evidence_group_id="replyto_mismatch"
    ),
    "EMAIL_002": DetectionRule(
        id="EMAIL_002",
        title="Display Name Spoofing",
        category="EMAIL",
        description="Email display name mimics a trusted organization but sender domain is unaffiliated.",
        weight=30,
        severity="high",
        evidence_group_id="display_name_spoof"
    ),
    "EMAIL_003": DetectionRule(
        id="EMAIL_003",
        title="Executive Impersonation + Wire Request (BEC)",
        category="EMAIL",
        description="Executive or authority impersonation combined with financial wire transfer request.",
        weight=30,
        severity="critical",
        evidence_group_id="bec_executive_wire"
    ),
    "EMAIL_004": DetectionRule(
        id="EMAIL_004",
        title="Suspicious Attachment Indicator",
        category="EMAIL",
        description="Email contains potentially dangerous attachment or archive payload.",
        weight=25,
        severity="high",
        evidence_group_id="suspicious_attachment"
    ),

    # -------------------------------------------------------------
    # 16. Webpage Rules
    # -------------------------------------------------------------
    "WEB_001": DetectionRule(
        id="WEB_001",
        title="Login Form on Suspicious Host",
        category="WEBPAGE",
        description="Webpage contains an authentication login form hosted on an unverified domain.",
        weight=20,
        severity="medium",
        evidence_group_id="web_login"
    ),
    "WEB_002": DetectionRule(
        id="WEB_002",
        title="Password Field on Impersonated Host",
        category="WEBPAGE",
        description="Password input field detected on a host exhibiting brand impersonation or high risk traits.",
        weight=25,
        severity="high",
        evidence_group_id="web_password"
    ),
    "WEB_003": DetectionRule(
        id="WEB_003",
        title="OTP Collection Field Detected",
        category="WEBPAGE",
        description="Webpage solicits one-time authentication codes in suspicious context.",
        weight=30,
        severity="high",
        evidence_group_id="web_otp"
    ),
    "WEB_004": DetectionRule(
        id="WEB_004",
        title="Credit Card / Payment Input Fields",
        category="WEBPAGE",
        description="Payment card number or CVV collection detected in unverified context.",
        weight=30,
        severity="high",
        evidence_group_id="web_payment"
    ),
    "WEB_005": DetectionRule(
        id="WEB_005",
        title="External Cross-Domain Form Exfiltration",
        category="WEBPAGE",
        description="HTML form action submits sensitive credentials to a third-party external destination domain.",
        weight=35,
        severity="critical",
        evidence_group_id="web_form_action"
    ),

    # -------------------------------------------------------------
    # 17. QR Rules
    # -------------------------------------------------------------
    "QR_001": DetectionRule(
        id="QR_001",
        title="QR Code Resolves to Suspicious Destination",
        category="QR",
        description="Decoded QR payload targets a domain exhibiting high risk characteristics.",
        weight=20,
        severity="medium",
        evidence_group_id="qr_suspicious_url"
    ),
    "QR_002": DetectionRule(
        id="QR_002",
        title="QR Code Resolves to Shortened URL",
        category="QR",
        description="QR code embeds a link shortener disguising the true destination.",
        weight=15,
        severity="low",
        evidence_group_id="qr_shortener"
    ),
    "QR_003": DetectionRule(
        id="QR_003",
        title="QR Code Leads to Credential Harvesting Page",
        category="QR",
        description="QR code directs user to an authentication or credential submission form.",
        weight=25,
        severity="high",
        evidence_group_id="qr_credentials"
    ),
    "QR_004": DetectionRule(
        id="QR_004",
        title="QR Code Initiates Suspicious Payment Request",
        category="QR",
        description="QR code encodes an unverified payment or crypto transaction payload.",
        weight=30,
        severity="high",
        evidence_group_id="qr_payment"
    ),

    # -------------------------------------------------------------
    # 18. Social Engineering Correlation Rules
    # -------------------------------------------------------------
    "COMBO_001": DetectionRule(
        id="COMBO_001",
        title="Correlated Urgency + Credential Harvesting",
        category="CORRELATION",
        description="Artificial panic/urgency combined with credential or OTP harvesting demands.",
        weight=25,
        severity="critical",
        evidence_group_id="combo_urgency_creds"
    ),
    "COMBO_002": DetectionRule(
        id="COMBO_002",
        title="Account Threat + Login Demand",
        category="CORRELATION",
        description="Threat of account deactivation combined with direct login request.",
        weight=25,
        severity="critical",
        evidence_group_id="combo_fear_login"
    ),
    "COMBO_003": DetectionRule(
        id="COMBO_003",
        title="Prize Lure + Advance Fee/Payment Request",
        category="CORRELATION",
        description="Unsolicited reward lure coupled with processing fee payment demands.",
        weight=30,
        severity="critical",
        evidence_group_id="combo_reward_pay"
    ),
    "COMBO_004": DetectionRule(
        id="COMBO_004",
        title="Authority Impersonation + Wire Request",
        category="CORRELATION",
        description="Brand or corporate executive impersonation paired with financial transaction.",
        weight=30,
        severity="critical",
        evidence_group_id="combo_exec_wire"
    ),
    "COMBO_005": DetectionRule(
        id="COMBO_005",
        title="OTP Request + External URL Link",
        category="CORRELATION",
        description="One-time password demand paired with an external redirect link.",
        weight=30,
        severity="critical",
        evidence_group_id="combo_otp_link"
    ),
    "COMBO_006": DetectionRule(
        id="COMBO_006",
        title="Password Solicitation on Suspicious Domain",
        category="CORRELATION",
        description="Credential collection combined with suspicious domain infrastructure.",
        weight=30,
        severity="critical",
        evidence_group_id="combo_pass_domain"
    )
}

