"""
CyberShield Local Threat Intelligence Feed
------------------------------------------
Indexes known malicious URLs and domains from the 651,191-record threat feed (malicious_phish.csv)
and provides real-time brand spoofing and threat signature detection.
"""

import os
import csv
import re
from typing import Set, Dict, Any, Optional
import tldextract

_INDEXED = False
_MALICIOUS_URLS: Set[str] = set()
_MALICIOUS_DOMAINS: Set[str] = set()

TRUSTED_DOMAINS = {
    "google.com", "google.co.in", "google.co.uk", "google.com.br", "gmail.com", "youtube.com",
    "wikipedia.org", "wikimedia.org", "github.com", "github.io", "gitlab.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "azure.com", "windows.com",
    "apple.com", "icloud.com", "itunes.com",
    "amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com",
    "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com", "linkedin.com",
    "reddit.com", "netflix.com", "spotify.com", "paypal.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "binance.com", "coinbase.com", "metamask.io", "stackoverflow.com",
    "stackexchange.com", "mozilla.org", "python.org", "docker.com", "medium.com", "cloudflare.com",
    "myspace.com", "vimeo.com", "dailymotion.com", "yahoo.com", "bing.com"
}

HIGH_VALUE_BRANDS = [
    "microsoft", "apple", "paypal", "google", "netflix", "amazon", "facebook", "instagram",
    "whatsapp", "chase", "wellsfargo", "bankofamerica", "binance", "coinbase", "metamask",
    "steam", "discord", "telegram", "sbi", "hdfc", "icici", "yahoo", "outlook", "office365",
    "citi", "barclays", "hsbc", "uber", "dropbox", "ebay", "walmart", "adobe"
]

PHISH_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security", "security-login",
    "account", "update", "confirm", "wallet", "restore", "recover", "seed", "portal",
    "suspended", "unlock", "alert", "auth", "authorize", "validate", "billing", "payment",
    "connect", "claim", "reactivate", "support", "helpdesk"
]


class LocalThreatIntelligenceFeed:
    @classmethod
    def initialize(cls):
        global _INDEXED, _MALICIOUS_URLS, _MALICIOUS_DOMAINS
        if _INDEXED:
            return

        search_paths = [
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "malicious_phish.csv"),
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "malicious_phish.csv"),
            os.path.join(os.getcwd(), "malicious_phish.csv"),
            "c:\\Users\\2007s\\OneDrive\\Documents\\CyberShieldWeb\\malicious_phish.csv"
        ]

        csv_path = None
        for p in search_paths:
            abs_p = os.path.abspath(p)
            if os.path.exists(abs_p):
                csv_path = abs_p
                break

        if not csv_path:
            _INDEXED = True
            return

        try:
            # Fast streaming load
            count = 0
            with open(csv_path, mode='r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    if len(row) >= 2:
                        url = row[0].strip().lower()
                        threat_type = row[1].strip().lower()
                        if threat_type in ["phishing", "malware", "defacement"]:
                            clean_url = url.replace("http://", "").replace("https://", "").replace("www.", "")
                            _MALICIOUS_URLS.add(clean_url)
                            _MALICIOUS_URLS.add(url)
                            
                            # Extract host domain
                            domain_part = clean_url.split('/')[0].split('?')[0]
                            if domain_part and domain_part not in TRUSTED_DOMAINS and not any(domain_part.endswith("." + td) for td in TRUSTED_DOMAINS):
                                _MALICIOUS_DOMAINS.add(domain_part)
                            count += 1
                            if count >= 150000:
                                break
            _INDEXED = True
        except Exception:
            _INDEXED = True

    @classmethod
    def lookup(cls, target: str) -> Optional[Dict[str, Any]]:
        cls.initialize()
        clean = target.strip().lower().replace("http://", "").replace("https://", "").replace("www.", "")
        url_no_scheme = target.strip().lower().replace("http://", "").replace("https://", "")

        # 1. Exact Database URL / Domain Match
        if target.lower() in _MALICIOUS_URLS or url_no_scheme in _MALICIOUS_URLS or clean in _MALICIOUS_URLS:
            return {
                "provider": "CyberShield Threat Feed",
                "malicious": True,
                "threat_type": "Exact Malicious URL Blacklist Match",
                "confidence": 0.98
            }

        domain_part = clean.split('/')[0].split('?')[0]
        if domain_part in _MALICIOUS_DOMAINS:
            return {
                "provider": "CyberShield Threat Feed",
                "malicious": True,
                "threat_type": f"Blacklisted Malicious Domain ({domain_part})",
                "confidence": 0.96
            }

        # 2. Dynamic Brand Spoofing Threat Correlation across ALL Brands
        try:
            ext = tldextract.extract(target)
            registered = ext.registered_domain.lower() if ext.registered_domain else ""
            subdomain = ext.subdomain.lower() if ext.subdomain else ""
            full_host = f"{subdomain}.{registered}".strip(".") if subdomain else registered

            # If not an official brand domain
            if registered and registered not in TRUSTED_DOMAINS and not any(registered == td or registered.endswith("." + td) for td in TRUSTED_DOMAINS):
                # Check for brand impersonation
                for b in HIGH_VALUE_BRANDS:
                    if b in full_host:
                        # Check for lure / security keywords or deceptive subdomains
                        has_lure = any(k in full_host or k in clean for k in PHISH_KEYWORDS)
                        if has_lure or b in subdomain or len(subdomain.split('.')) >= 2:
                            return {
                                "provider": "CyberShield Threat Feed",
                                "malicious": True,
                                "threat_type": f"Brand Impersonation Phishing Host ({b.title()})",
                                "confidence": 0.96
                            }
        except Exception:
            pass

        return None
